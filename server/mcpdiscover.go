package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/mcphttp"
)

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
	if err := validateMCPConfig(m); err != nil {
		return nil, err
	}
	switch m.Transport {
	case "stdio":
		env, err := resolveMCPEnv(m.Env)
		if err != nil {
			return nil, err
		}
		return mcp.NewStdioClient(ctx, m.Name, m.Command, env, jsonStrSlice(m.Args)...)
	case "http":
		// env map doubles as HTTP headers (e.g. Authorization).
		env, err := resolveMCPEnv(m.Env)
		if err != nil {
			return nil, err
		}
		return mcphttp.New(ctx, m.Name, m.URL, env, m.Insecure)
	case "sse":
		env, err := resolveMCPEnv(m.Env)
		if err != nil {
			return nil, err
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, env, m.Insecure)
	default:
		return nil, fmt.Errorf("未知传输方式 %q", m.Transport)
	}
}

func validateMCPConfig(m *db.MCPServer) error {
	if m == nil {
		return fmt.Errorf("MCP 配置为空")
	}
	switch m.Transport {
	case "stdio":
		if strings.TrimSpace(m.Command) == "" {
			return fmt.Errorf("stdio 传输缺少命令")
		}
	case "http", "sse":
		if strings.TrimSpace(m.URL) == "" {
			return fmt.Errorf("%s 传输缺少 URL", m.Transport)
		}
	default:
		return fmt.Errorf("未知传输方式 %q", m.Transport)
	}
	return nil
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	cl, err := connectMCP(ctx, m)
	if err != nil {
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		return err
	}
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf("[mcp] %s 发现 %d 个工具并已缓存", m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers (npx) at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] 启动自动发现: 读取列表失败: %v", err)
		return
	}
	for _, m := range servers {
		if !m.Enabled {
			continue
		}
		if err := validateMCPConfig(m); err != nil {
			log.Printf("[mcp] 启动自动发现跳过 %s: %v", m.Name, err)
			continue
		}
		if len(m.Tools) > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf("[mcp] 启动自动发现 %s 失败: %v", m.Name, err)
		}
		cancel()
	}
}
