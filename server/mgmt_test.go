package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMgmtAPI exercises the PostgreSQL-backed management API through the real mux.
func TestMgmtAPI(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping management API test", err)
	}
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping management API test")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	do := func(method, path string, body any) (int, map[string]any) {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// agents list — must include at least the seeded builtins
	code, out := do("GET", "/api/agents", nil)
	if code != 200 {
		t.Fatalf("GET agents: %d", code)
	}
	if ags, _ := out["agents"].([]any); len(ags) < 5 {
		t.Fatalf("want >=5 agents (seeded builtins), got %d", len(ags))
	}

	// invalid template var → 400 (catalog whitelist)
	code, out = do("PUT", "/api/agents/planner/prompt", map[string]string{"template": "hi {{.Nope}}"})
	if code != 400 {
		t.Fatalf("bad var should be 400, got %d (%v)", code, out)
	}

	// valid template using seeded catalog vars → 200
	code, _ = do("PUT", "/api/agents/planner/prompt", map[string]string{"template": "你是规划者，目标：{{.Goal}}，摘要 {{.AssetSummary}}"})
	if code != 200 {
		t.Fatalf("valid prompt save: %d", code)
	}

	// preview renders with catalog examples
	code, out = do("POST", "/api/agents/planner/prompt/preview", map[string]any{})
	if code != 200 {
		t.Fatalf("preview: %d", code)
	}
	if rendered, _ := out["rendered"].(string); rendered == "" || rendered == "你是规划者，目标：{{.Goal}}，摘要 {{.AssetSummary}}" {
		t.Fatalf("preview did not substitute: %q", out["rendered"])
	}

	// mcp create → visible to planner → resource-side sees planner → delete clears it
	// Remove any leftover from prior run to keep the test idempotent.
	m.pg.Exec(`DELETE FROM mcp_servers WHERE name = 't-itest'`)
	t.Setenv("ARTEX_MCP_SECRET_MGMT_TEST", "fixture-api-secret")
	code, out = do("POST", "/api/mcp", map[string]any{
		"name": "t-itest", "transport": "stdio", "command": "x", "enabled": false,
		"env": map[string]string{"TOKEN": "${ARTEX_MCP_SECRET_MGMT_TEST}"},
	})
	if code != 200 {
		t.Fatalf("create mcp: %d", code)
	}
	mid := int64(out["id"].(float64))
	code, out = do("GET", "/api/mcp", nil)
	if code != 200 {
		t.Fatalf("list mcp: %d", code)
	}
	encoded, err := json.Marshal(out["servers"])
	if err != nil {
		t.Fatalf("encode listed mcp servers: %v", err)
	}
	if strings.Contains(string(encoded), "fixture-api-secret") || !strings.Contains(string(encoded), "ARTEX_MCP_SECRET_MGMT_TEST") {
		t.Fatal("MCP list API must return the reference without resolving the secret")
	}
	servers, ok := out["servers"].([]any)
	if !ok {
		t.Fatalf("MCP list response has an invalid servers field: %#v", out["servers"])
	}
	found := false
	for _, item := range servers {
		server, ok := item.(map[string]any)
		if !ok || server["name"] != "t-itest" {
			continue
		}
		found = true
		if enabled, ok := server["enabled"].(bool); !ok || enabled {
			t.Fatalf("new MCP should remain disabled: %#v", server["enabled"])
		}
	}
	if !found {
		t.Fatal("new MCP was missing from the list response")
	}
	code, out = do("GET", "/api/visibility/mcp/"+itoaTest(mid), nil)
	if code != 200 {
		t.Fatalf("initial resource visibility: %d", code)
	}
	if agents, _ := out["agents"].([]any); len(agents) != 0 {
		t.Fatalf("new MCP should not be assigned automatically: %v", agents)
	}

	ag, _ := m.pg.GetAgentByKey("planner")
	code, _ = do("PUT", "/api/agents/planner/visibility", map[string]any{"mcp": []int64{mid}, "skill": []int64{}})
	if code != 200 {
		t.Fatalf("set visibility: %d", code)
	}
	code, out = do("GET", "/api/visibility/mcp/"+itoaTest(mid), nil)
	if code != 200 {
		t.Fatalf("resource visibility: %d", code)
	}
	if agents, _ := out["agents"].([]any); len(agents) != 1 || agents[0].(string) != itoaTest(ag.ID) {
		t.Fatalf("resource-side should list planner, got %v", out["agents"])
	}

	// cleanup
	do("DELETE", "/api/mcp/"+itoaTest(mid), nil)
	m.pg.Exec(`DELETE FROM agent_prompts WHERE agent_id=$1`, ag.ID)
	m.pg.Exec(`UPDATE agents SET current_prompt_id=NULL WHERE id=$1`, ag.ID)
}

func itoaTest(n int64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
