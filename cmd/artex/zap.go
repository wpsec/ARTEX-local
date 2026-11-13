package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

const zapMCPAddress = "127.0.0.1:8282"

type zapRuntime struct {
	cmd        *exec.Cmd
	done       chan struct{}
	ready      chan error
	exitErr    error
	configPath string
	home       string
}

type redactingWriter struct {
	mu      sync.Mutex
	dst     io.Writer
	secret  string
	pending string
}

func (writer *redactingWriter) Write(data []byte) (int, error) {
	written := len(data)
	if written == 0 {
		return 0, nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()

	if writer.secret == "" {
		_, err := writer.dst.Write(data)
		return written, err
	}

	combined := writer.pending + string(data)
	flushUntil := len(combined)
	maxPrefix := len(writer.secret) - 1
	if maxPrefix > len(combined) {
		maxPrefix = len(combined)
	}
	for size := maxPrefix; size > 0; size-- {
		if strings.HasSuffix(combined, writer.secret[:size]) {
			flushUntil = len(combined) - size
			break
		}
	}

	output := strings.ReplaceAll(combined[:flushUntil], writer.secret, "[REDACTED]")
	writer.pending = combined[flushUntil:]
	if output == "" {
		return written, nil
	}
	_, err := io.WriteString(writer.dst, output)
	return written, err
}

func (writer *redactingWriter) Flush() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	output := strings.ReplaceAll(writer.pending, writer.secret, "[REDACTED]")
	writer.pending = ""
	if output == "" {
		return nil
	}
	_, err := io.WriteString(writer.dst, output)
	return err
}

func startZAPRuntime() (*zapRuntime, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("ARTEX_ZAP_ENABLED")), "true") {
		return nil, nil
	}

	key, err := zapSecret()
	if err != nil {
		return nil, fmt.Errorf("生成 ZAP 密钥失败: %w", err)
	}

	configPath, err := writeZAPConfig(key)
	if err != nil {
		return nil, fmt.Errorf("创建 ZAP 配置失败: %w", err)
	}
	home, err := os.MkdirTemp("", "artex-zap-home-")
	if err != nil {
		_ = os.Remove(configPath)
		return nil, fmt.Errorf("创建 ZAP 临时目录失败: %w", err)
	}

	cmd := exec.Command("/opt/zap/zap.sh", "-daemon", "-silent", "-dir", home, "-loglevel", "WARN", "-configfile", configPath)
	stdout := &redactingWriter{dst: os.Stdout, secret: key}
	stderr := &redactingWriter{dst: os.Stderr, secret: key}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = os.Remove(configPath)
		_ = os.RemoveAll(home)
		return nil, fmt.Errorf("启动 ZAP 失败: %w", err)
	}

	runtime := &zapRuntime{
		cmd:        cmd,
		done:       make(chan struct{}),
		ready:      make(chan error, 1),
		configPath: configPath,
		home:       home,
	}
	go func() {
		runtime.exitErr = cmd.Wait()
		if err := stdout.Flush(); err != nil {
			log.Printf("[zap] 转发标准输出失败: %v", err)
		}
		if err := stderr.Flush(); err != nil {
			log.Printf("[zap] 转发标准错误失败: %v", err)
		}
		close(runtime.done)
	}()
	go func() {
		runtime.ready <- waitForZAP(runtime, 90*time.Second)
		close(runtime.ready)
	}()
	return runtime, nil
}

func zapSecret() (string, error) {
	if key := os.Getenv("ARTEX_MCP_SECRET_ZAP_KEY"); key != "" {
		return key, nil
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(raw[:])
	if err := os.Setenv("ARTEX_MCP_SECRET_ZAP_KEY", key); err != nil {
		return "", err
	}
	return key, nil
}

func writeZAPConfig(key string) (string, error) {
	if strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("ZAP 密钥不能包含控制字符")
	}
	file, err := os.CreateTemp("", "artex-zap-*.properties")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	escapedKey := strings.ReplaceAll(key, `\`, `\\`)
	contents := strings.Join([]string{
		"mcp.enabled=true",
		"mcp.port=8282",
		"mcp.securityKeyEnabled=true",
		"mcp.securityKey=" + escapedKey,
		"mcp.secureOnly=false",
		"",
	}, "\n")
	if _, err := file.WriteString(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func waitForZAP(runtime *zapRuntime, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", zapMCPAddress, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-runtime.done:
			if runtime.exitErr == nil {
				return fmt.Errorf("ZAP 在 MCP listener 就绪前退出")
			}
			return fmt.Errorf("ZAP 在 MCP listener 就绪前退出: %w", runtime.exitErr)
		default:
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("等待 ZAP MCP listener 超时")
}

func (runtime *zapRuntime) Done() <-chan struct{} {
	if runtime == nil {
		return nil
	}
	return runtime.done
}

func (runtime *zapRuntime) Ready() <-chan error {
	if runtime == nil {
		return nil
	}
	return runtime.ready
}

func (runtime *zapRuntime) Close() {
	if runtime == nil {
		return
	}
	if runtime.cmd.Process != nil {
		_ = runtime.cmd.Process.Signal(os.Interrupt)
		select {
		case <-runtime.done:
		case <-time.After(10 * time.Second):
			_ = runtime.cmd.Process.Kill()
			<-runtime.done
		}
	}
	_ = os.Remove(runtime.configPath)
	_ = os.RemoveAll(filepath.Clean(runtime.home))
}
