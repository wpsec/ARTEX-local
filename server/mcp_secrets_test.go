package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wpsec/ARTEX-local/db"
)

func TestResolveMCPEnvWithLookup(t *testing.T) {
	const secret = "resolved-env-value"
	got, err := resolveMCPEnvWithLookup(map[string]string{
		"Authorization": "Bearer ${ARTEX_MCP_SECRET_TOKEN}",
		"LITERAL":       "unchanged",
	}, func(name string) (string, bool) {
		if name == "ARTEX_MCP_SECRET_TOKEN" {
			return secret, true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["Authorization"] != "Bearer "+secret {
		t.Fatalf("resolved authorization header mismatch")
	}
	if got["LITERAL"] != "unchanged" {
		t.Fatalf("literal value changed")
	}
}

func TestResolveMCPEnvWithLookupMissingSecret(t *testing.T) {
	_, err := resolveMCPEnvWithLookup(map[string]string{
		"Authorization": "${ARTEX_MCP_SECRET_MISSING}",
	}, func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "ARTEX_MCP_SECRET_MISSING") {
		t.Fatalf("expected missing variable name in error, got %v", err)
	}
}

func TestResolveMCPEnvWithLookupRejectsMalformedReference(t *testing.T) {
	_, err := resolveMCPEnvWithLookup(map[string]string{
		"Authorization": "${ARTEX_MCP_SECRET_bad}",
	}, func(string) (string, bool) { return "must-not-be-used", true })
	if err == nil || strings.Contains(err.Error(), "must-not-be-used") {
		t.Fatalf("expected safe malformed-reference error, got %v", err)
	}
}

func TestResolveMCPEnvKeepsReferenceOutOfStoredConfig(t *testing.T) {
	raw := json.RawMessage(`{"Authorization":"${ARTEX_MCP_SECRET_TOKEN}"}`)
	resolved, err := resolveMCPEnvWithLookup(jsonStrMap(raw), func(string) (string, bool) {
		return "resolved-env-value", true
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), resolved["Authorization"]) {
		t.Fatal("resolved secret was written into the stored configuration")
	}
	encoded, err := json.Marshal(db.MCPServer{Env: raw})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "resolved-env-value") || !strings.Contains(string(encoded), "ARTEX_MCP_SECRET_TOKEN") {
		t.Fatal("MCP config serialization exposed the resolved secret or lost its reference")
	}
}

func TestConnectMCPHTTPResolvesSecretAsHeader(t *testing.T) {
	const secret = "fixture-http-token"
	t.Setenv("ARTEX_MCP_SECRET_HTTP_TEST", secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
			http.Error(w, "authorization header missing", http.StatusUnauthorized)
			return
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
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
				"serverInfo":      map[string]any{"name": "fixture", "version": "1"},
			}
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{
					"name": "echo", "description": "fixture tool",
					"inputSchema": map[string]any{"type": "object"},
				},
			}}
		default:
			http.Error(w, "unsupported JSON-RPC method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		}); err != nil {
			t.Errorf("write JSON-RPC response: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := connectMCP(ctx, &db.MCPServer{
		Name:      "http-fixture",
		Transport: "http",
		URL:       srv.URL,
		Env:       json.RawMessage(`{"Authorization":"Bearer ${ARTEX_MCP_SECRET_HTTP_TEST}"}`),
	})
	if err != nil {
		t.Fatalf("connect MCP over HTTP: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close MCP client: %v", err)
		}
	}()

	tools, err := client.Tools(ctx)
	if err != nil {
		t.Fatalf("list MCP tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name() != "mcp__http-fixture__echo" {
		t.Fatalf("unexpected MCP tools: %#v", tools)
	}
}

func TestScopeSentryStatusResolvesSecretHeader(t *testing.T) {
	const secret = "fixture-scopesentry-token"
	t.Setenv("ARTEX_MCP_SECRET_SCOPESENTRY_TEST", secret)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != secret {
			http.Error(w, "API key header missing", http.StatusUnauthorized)
			return
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON-RPC request", http.StatusBadRequest)
			return
		}
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method != "initialize" && req.Method != "tools/list" {
			http.Error(w, "unsupported JSON-RPC method", http.StatusBadRequest)
			return
		}
		result := map[string]any{"tools": []any{}}
		if req.Method == "initialize" {
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fixture", "version": "1"},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		}); err != nil {
			t.Errorf("write JSON-RPC response: %v", err)
		}
	}))
	defer srv.Close()

	manager, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable: %v", err)
	}
	if manager.pg == nil {
		t.Skip("postgres unavailable")
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close test manager: %v", err)
		}
	})

	var original *db.MCPServer
	servers, err := manager.pg.ListMCP()
	if err != nil {
		t.Fatalf("list MCP servers: %v", err)
	}
	for _, candidate := range servers {
		if candidate.Name == scopeSentryMCPName {
			copy := *candidate
			copy.Args = append(json.RawMessage(nil), candidate.Args...)
			copy.Env = append(json.RawMessage(nil), candidate.Env...)
			original = &copy
			break
		}
	}
	if original == nil {
		t.Fatalf("seeded MCP %q is missing", scopeSentryMCPName)
	}
	updated := *original
	updated.Transport = "http"
	updated.URL = srv.URL
	updated.Env = json.RawMessage(`{"X-API-Key":"${ARTEX_MCP_SECRET_SCOPESENTRY_TEST}"}`)
	updated.Enabled = true
	if _, err := manager.pg.SaveMCP(&updated); err != nil {
		t.Fatalf("configure ScopeSentry fixture: %v", err)
	}
	t.Cleanup(func() {
		if _, err := manager.pg.SaveMCP(original); err != nil {
			t.Errorf("restore ScopeSentry configuration: %v", err)
		}
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sync/scopesentry/status", nil)
	(&Server{m: manager}).syncSSStatus(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ScopeSentry status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode ScopeSentry status: %v", err)
	}
	for _, key := range []string{"configured", "enabled", "reachable"} {
		if got, ok := status[key].(bool); !ok || !got {
			t.Fatalf("ScopeSentry status %q = %v, want true", key, status[key])
		}
	}
}
