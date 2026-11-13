package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		if err := pg.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.SetAgentSkillVisibility(ag.ID, orig); err != nil {
			t.Errorf("restore skill visibility: %v", err)
		}
	})

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteSkillVisibility(skillName); err != nil {
			t.Errorf("remove test skill visibility: %v", err)
		}
	})

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}

func TestWireAgentAugmentUnlocksSeededZAPAfterSkillLoad(t *testing.T) {
	const (
		skillName  = "web-app-penetration-testing"
		serverName = "OWASP ZAP"
		toolReply  = "fixture ZAP version 2.17.0"
	)
	var calls atomic.Int32
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON-RPC request", http.StatusBadRequest)
			return
		}
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fixture-zap", "version": "1"},
			}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{
				"name": "version", "description": "Return the fixture ZAP version.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			}}}
		case "tools/call":
			if req.Params.Name != "version" {
				http.Error(w, "unknown fixture tool", http.StatusBadRequest)
				return
			}
			calls.Add(1)
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": toolReply}}}
		default:
			http.Error(w, "unsupported JSON-RPC method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		}); err != nil {
			t.Errorf("write fixture MCP response: %v", err)
		}
	}))
	t.Cleanup(mcp.Close)

	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		if err := pg.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	if err := pg.SeedBuiltinMCPServers(); err != nil {
		t.Fatal(err)
	}
	servers, err := pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	var zap *db.MCPServer
	for _, candidate := range servers {
		if candidate.Name == serverName {
			copy := *candidate
			zap = &copy
			break
		}
	}
	if zap == nil {
		t.Fatalf("seeded MCP %q is missing", serverName)
	}
	zap.Transport = "http"
	zap.URL = mcp.URL
	zap.Env = json.RawMessage(`{}`)
	zap.Enabled = true
	if _, err := pg.SaveMCP(zap); err != nil {
		t.Fatalf("configure fixture MCP: %v", err)
	}
	penTest, err := pg.GetAgentByKey("pentest")
	if err != nil {
		t.Fatalf("get built-in pentest agent: %v", err)
	}
	if penTest == nil {
		t.Fatal("built-in pentest agent is missing")
	}
	if err := pg.SetAgentSkillVisibility(penTest.ID, []string{skillName}); err != nil {
		t.Fatal(err)
	}

	previousAugment := agent.ToolAugment
	wireAgentAugment(pg, filepath.Join("..", "skills"), nil)
	t.Cleanup(func() { agent.ToolAugment = previousAugment })
	tools, deferred, cleanup := agent.ToolAugment(context.Background(), penTest.Key)
	t.Cleanup(cleanup)
	if len(deferred.Deferred) != 1 {
		t.Fatalf("expected one deferred ZAP tool, got %v", deferred.Deferred)
	}
	toolName := deferred.Deferred[0]
	if len(deferred.GlobalNames) != 0 || deferred.Unlock == nil || deferred.Unlock.Has(toolName) {
		t.Fatalf("ZAP tool should stay hidden and locked before Skill load: %+v", deferred)
	}
	var skillTool, zapTool actool.CoreTool
	for _, tool := range tools {
		switch tool.Name() {
		case "Skill":
			skillTool = tool
		case toolName:
			zapTool = tool
		}
	}
	if skillTool == nil || zapTool == nil {
		t.Fatal("wireAgentAugment did not return the Skill tool and deferred MCP tool")
	}
	if _, err := skillTool.Call(context.Background(), json.RawMessage(`{"name":"`+skillName+`"}`), nil); err != nil {
		t.Fatalf("load Web testing Skill: %v", err)
	}
	if !deferred.Unlock.Has(toolName) {
		t.Fatalf("loading Skill did not unlock %q", toolName)
	}
	result, err := zapTool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("call fixture ZAP tool: %v", err)
	}
	var output strings.Builder
	for _, block := range result.Content {
		output.WriteString(block.Text)
	}
	if calls.Load() != 1 || !strings.Contains(output.String(), toolReply) {
		t.Fatalf("fixture MCP tool was not called exactly once: calls=%d result=%q", calls.Load(), output.String())
	}
}
