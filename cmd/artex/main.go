// Command artex runs the ARTEX backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/config"
	"github.com/wpsec/ARTEX-local/selfupdate"
	"github.com/wpsec/ARTEX-local/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to the current app version for manual builds.
var version = "2.2.1"

const banner = `
    _    ____ _____ _______  __
   / \  |  _ \_   _| ____\ \/ /
  / _ \ | |_) || | |  _|  \  /
 / ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  AI 自主渗透测试系统")
	fmt.Printf("  版本 %s  ·  %s/%s  ·  %s  ·  监听 %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr    = flag.String("addr", ":8787", "HTTP listen address")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
	)
	flag.Parse()

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] 配置文件: %s", cfgPath)
	} else {
		log.Printf("[config] 配置文件: %s (不存在 — 将仅尝试环境变量 ARTEX_PG_DSN)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	zap, err := startZAPRuntime()
	if err != nil {
		log.Printf("[zap] 启动失败，ARTEX 将继续运行: %v", err)
	}
	defer func() {
		if zap != nil {
			zap.Close()
		}
	}()
	var zapReady <-chan error
	var zapDone <-chan struct{}
	if zap != nil {
		zapReady = zap.Ready()
		zapDone = zap.Done()
		select {
		case readyErr := <-zapReady:
			zapReady = nil
			if readyErr != nil {
				log.Printf("[zap] MCP listener 未就绪，ARTEX 将继续运行: %v", readyErr)
				zap.Close()
				zap = nil
				zapDone = nil
			}
		case <-ctx.Done():
			return 0
		}
	}

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Printf("open stores: %v", err)
		return 1
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] skill 目录: %s", skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)

	go func() {
		log.Printf("ARTEX %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	// Exit codes tell start.sh whether to stop, restart after a failure, or relaunch
	// after a staged update so Bootstrap can install the new build.
	code := 0

runLoop:
	for {
		select {
		case <-ctx.Done():
			break runLoop
		case <-zapDone:
			if ctx.Err() == nil {
				log.Printf("[zap] MCP 服务意外退出: %v，重启 ARTEX 进程以恢复 ZAP", zap.exitErr)
				code = 1
			}
			zap.Close()
			zap = nil
			zapDone = nil
			zapReady = nil
			break runLoop
		case err := <-serveErr:
			log.Printf("serve: %v", err)
			code = 1
			shutdown(agent.AbortShutdown)
			break runLoop
		case readyErr := <-zapReady:
			if readyErr != nil {
				log.Printf("[zap] MCP listener 未就绪，ARTEX 将继续运行: %v", readyErr)
				zap.Close()
				zap = nil
				zapDone = nil
			}
			zapReady = nil
		case <-server.RestartRequested():
			code = selfupdate.ExitRestart
			shutdown(agent.AbortShutdown)
			break runLoop
		}
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return code
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
