package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/norma/skill"
)

func TestBundledWebSkillsReferenceSeededZAPMCP(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("load bundled skills: %v", err)
	}

	for _, name := range []string{"web-app-penetration-testing", "api-security-testing"} {
		s, ok := reg.Get(name)
		if !ok {
			t.Fatalf("bundled Skill %q was not loaded", name)
		}
		found := false
		for _, mcp := range s.MCPs {
			if mcp == builtinOWASPZAPMCPName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Skill %q does not declare the seeded ZAP MCP name %q; mcps=%v", name, builtinOWASPZAPMCPName, s.MCPs)
		}
	}
}

// TestPoolProfilesOrder pins the failover chain query: keyless profiles can't
// serve a request and excluded ones aren't fallback targets, so neither belongs
// in the chain; the rest come back by priority, highest first.
// Deliberately does NOT touch is_default — flipping the active profile would be a
// side effect on the shared dev database.
func TestPoolProfilesOrder(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	mk := func(name string, priority int, exclude bool, key string) int64 {
		id, err := d.SaveProfile(&LLMProfile{
			Name: name, Format: "openai", Model: "m", APIKey: key,
			Priority: priority, PoolExclude: exclude,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
		return id
	}
	lo := mk("t-pool-lo", 1, false, "k1")
	hi := mk("t-pool-hi", 9, false, "k2")
	mk("t-pool-excluded", 99, true, "k3") // excluded despite the top priority
	mk("t-pool-nokey", 50, false, "")     // no key → cannot serve anything

	chain, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for _, p := range chain {
		switch p.Name {
		case "t-pool-lo", "t-pool-hi":
			got = append(got, p.ID)
		case "t-pool-excluded":
			t.Fatal("pool_exclude profile entered the failover chain")
		case "t-pool-nokey":
			t.Fatal("keyless profile entered the failover chain")
		}
	}
	if len(got) != 2 || got[0] != hi || got[1] != lo {
		t.Fatalf("chain order = %v, want [hi=%d lo=%d]", got, hi, lo)
	}
}

func TestUpgradePromptIfCurrentPreservesCustomAndHistory(t *testing.T) {
	dsn := isolatedTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	a, err := d.CreateAgent("test_prompt_upgrade", "test prompt upgrade", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SavePrompt(a.ID, "old default", "built-in", "system"); err != nil {
		t.Fatal(err)
	}
	changed, err := d.UpgradePromptIfCurrent(a.ID, "old default", "new default")
	if err != nil || !changed {
		t.Fatalf("upgrade old default: changed=%v err=%v", changed, err)
	}
	versions, err := d.ListPromptVersions(a.ID)
	if err != nil || len(versions) != 2 || versions[0].Template != "new default" || versions[1].Template != "old default" {
		t.Fatalf("prompt history: %+v err=%v", versions, err)
	}
	changed, err = d.UpgradePromptIfCurrent(a.ID, "old default", "new default")
	if err != nil || changed {
		t.Fatalf("repeat upgrade: changed=%v err=%v", changed, err)
	}
	if _, err := d.SavePrompt(a.ID, "customized", "user", "user"); err != nil {
		t.Fatal(err)
	}
	changed, err = d.UpgradePromptIfCurrent(a.ID, "old default", "new default")
	current, currentErr := d.CurrentPrompt(a.ID)
	versions, historyErr := d.ListPromptVersions(a.ID)
	if err != nil || changed || currentErr != nil || current != "customized" || historyErr != nil || len(versions) != 3 {
		t.Fatalf("custom prompt changed: changed=%v current=%q versions=%d errors=%v/%v/%v", changed, current, len(versions), err, currentErr, historyErr)
	}
	for i := 0; i < 10; i++ {
		if _, err := d.SavePrompt(a.ID, "old default", "fixture", "system"); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			_, err := d.UpgradePromptIfCurrent(a.ID, "old default", "new default")
			errs <- err
		}()
		go func() {
			<-start
			_, err := d.SavePrompt(a.ID, "concurrent user edit", "user", "user")
			errs <- err
		}()
		close(start)
		for j := 0; j < 2; j++ {
			if err := <-errs; err != nil {
				t.Fatalf("concurrent prompt write: %v", err)
			}
		}
		current, err := d.CurrentPrompt(a.ID)
		if err != nil || current != "concurrent user edit" {
			t.Fatalf("concurrent user edit lost: current=%q err=%v", current, err)
		}
	}
	for i := 0; i < 10; i++ {
		fresh, err := d.CreateAgent(fmt.Sprintf("test_prompt_seed_%d", i), "seed race", "")
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			errs <- d.SeedPromptIfEmpty(fresh.ID, "seed default")
		}()
		go func() {
			<-start
			_, err := d.SavePrompt(fresh.ID, "concurrent user edit", "user", "user")
			errs <- err
		}()
		close(start)
		for j := 0; j < 2; j++ {
			if err := <-errs; err != nil {
				t.Fatalf("concurrent seed and edit: %v", err)
			}
		}
		current, err := d.CurrentPrompt(fresh.ID)
		if err != nil || current != "concurrent user edit" {
			t.Fatalf("seed overwrote concurrent user edit: current=%q err=%v", current, err)
		}
	}
}

func TestDeleteProfileContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var d DB
	if err := d.DeleteProfileContext(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeleteProfileContext error=%v, want context cancellation", err)
	}
}

func TestBuiltinSkillVisibilitySeedsAndPreservesOptOut(t *testing.T) {
	dsn := isolatedTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("open isolated PostgreSQL database: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	reopen := func() {
		next, err := Open(dsn)
		if err != nil {
			t.Fatalf("reopen database: %v", err)
		}
		if err := d.Close(); err != nil {
			if closeErr := next.Close(); closeErr != nil {
				t.Errorf("close replacement database after reopen failure: %v", closeErr)
			}
			t.Fatalf("close database before reopen: %v", err)
		}
		d = next
	}

	ag, err := d.GetAgentByKey("worker")
	if err != nil || ag == nil {
		t.Fatalf("worker agent: %v", err)
	}

	skillNames := []string{
		"application-security-testing",
		"web-app-penetration-testing",
		"api-security-testing",
		"owasp-top-10-testing",
		"find-security-vulnerabilities-in-code",
		"playwright-cli",
	}
	for _, name := range skillNames {
		if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, ag.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	reopen()
	visible, err := d.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range skillNames {
		if !hasSkillName(visible, name) {
			t.Errorf("default skill %s not visible to worker: %v", name, visible)
		}
	}

	if err := d.SetAgentSkillVisibility(ag.ID, []string{"api-recon"}); err != nil {
		t.Fatal(err)
	}
	reopen()
	visible, err = d.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range skillNames {
		if hasSkillName(visible, name) {
			t.Errorf("builtin seed restored manually disabled skill %s: %v", name, visible)
		}
	}

	if err := d.ToggleSkillVisibility(ag.ID, skillNames[0], true); err != nil {
		t.Fatal(err)
	}
	reopen()
	visible, err = d.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSkillName(visible, skillNames[0]) {
		t.Fatalf("explicitly enabled skill %s became hidden: %v", skillNames[0], visible)
	}
	if err := d.ToggleSkillVisibility(ag.ID, skillNames[0], false); err != nil {
		t.Fatal(err)
	}
	reopen()
	visible, err = d.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hasSkillName(visible, skillNames[0]) {
		t.Fatalf("builtin seed restored manually toggled-off skill %s: %v", skillNames[0], visible)
	}
}

func isolatedTestDSN(t *testing.T) string {
	t.Helper()
	baseDSN := testDSN(t)
	baseURL, err := url.Parse(baseDSN)
	if err != nil || (baseURL.Scheme != "postgres" && baseURL.Scheme != "postgresql") {
		t.Skipf("configured PostgreSQL DSN is not a URL")
	}

	databaseName := fmt.Sprintf("artex_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	testURL := *baseURL
	testURL.Path = "/" + databaseName
	testURL.RawPath = ""
	adminURL := *baseURL
	adminURL.Path = "/postgres"
	adminURL.RawPath = ""
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Skipf("connect to PostgreSQL for isolated test database: %v", err)
	}
	if err := admin.Ping(); err != nil {
		if closeErr := admin.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL setup connection: %v", closeErr)
		}
		t.Skipf("PostgreSQL unavailable for isolated test database: %v", err)
	}
	if _, err := admin.Exec(`CREATE DATABASE "` + databaseName + `"`); err != nil {
		if closeErr := admin.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL setup connection: %v", closeErr)
		}
		t.Skipf("cannot create isolated test database: %v", err)
	}
	t.Cleanup(func() {
		admin, err := sql.Open("pgx", adminURL.String())
		if err != nil {
			t.Errorf("connect to PostgreSQL for test database cleanup: %v", err)
			return
		}
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + databaseName + `"`); err != nil {
			t.Errorf("drop isolated test database: %v", err)
		}
		if err := admin.Close(); err != nil {
			t.Errorf("close PostgreSQL cleanup connection: %v", err)
		}
	})
	if err := admin.Close(); err != nil {
		t.Fatalf("close PostgreSQL setup connection: %v", err)
	}
	return testURL.String()
}

func hasSkillName(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}

func TestConfigStores(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// LLM profile: save, active, key never serialized
	pid, err := d.SaveProfile(&LLMProfile{Name: "t-default", Format: "openai", Model: "gpt-x", APIKey: "secret123"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, pid)
	if err := d.SetActiveProfile(pid); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteProfile(pid); !errors.Is(err, ErrActiveLLMProfileDelete) {
		t.Fatalf("deleting active profile error=%v, want %v", err, ErrActiveLLMProfileDelete)
	}
	act, err := d.ActiveProfile()
	if err != nil || act == nil || act.APIKey != "secret123" {
		t.Fatalf("active profile/key: %+v err=%v", act, err)
	}
	// list must hide the key, expose hint
	list, _ := d.ListProfiles()
	for _, p := range list {
		if p.ID == pid {
			b, _ := json.Marshal(p)
			if string(b) == "" || contains(string(b), "secret123") {
				t.Fatalf("api key leaked in list json: %s", b)
			}
			if p.APIKeyHint != "…t123" {
				t.Fatalf("hint want …t123, got %q", p.APIKeyHint)
			}
		}
	}

	// agents seeded; prompt versioning
	ag, err := d.GetAgentByKey("planner")
	if err != nil || ag == nil {
		t.Fatalf("planner agent: %v", err)
	}
	v1, err := d.SavePrompt(ag.ID, "你是规划者 {{.Goal}}", "init", "test")
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := d.SavePrompt(ag.ID, "你是规划者 v2 {{.Goal}} {{.Scope}}", "edit", "test")
	if v2 != v1+1 {
		t.Fatalf("version should increment: %d -> %d", v1, v2)
	}
	cur, _ := d.CurrentPrompt(ag.ID)
	if cur != "你是规划者 v2 {{.Goal}} {{.Scope}}" {
		t.Fatalf("current prompt wrong: %q", cur)
	}
	vers, _ := d.ListPromptVersions(ag.ID)
	if len(vers) < 2 {
		t.Fatalf("want >=2 versions, got %d", len(vers))
	}
	pv, _ := d.PromptVars(ag.ID)
	// planner must have at least the seeded catalog vars (Goal, AssetSummary)
	if len(pv) < 2 {
		t.Fatalf("planner catalog want >=2 vars, got %d", len(pv))
	}
	d.Exec(`DELETE FROM agent_prompts WHERE agent_id=$1`, ag.ID)
	d.Exec(`UPDATE agents SET current_prompt_id=NULL WHERE id=$1`, ag.ID)

	// mcp + skill + visibility (bidirectional via one join)
	// Clean up any leftover MCP from prior runs to keep this test idempotent.
	d.Exec(`DELETE FROM mcp_servers WHERE name = 't-gh'`)
	mid, err := d.SaveMCP(&MCPServer{Name: "t-gh", Transport: "stdio", Command: "npx", Args: json.RawMessage(`["server-github"]`), Env: json.RawMessage(`{"GITHUB_TOKEN":"x"}`), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// agent-side write. MCP is id-keyed (generic visibility join); skills are now
	// filesystem-based, so their visibility is keyed by skill (directory) name in a
	// dedicated table. Clear any pre-existing MCP visibility rows so the assertions
	// below isolate on exactly what this test sets.
	d.Exec(`DELETE FROM agent_visibility WHERE agent_id = $1 AND resource_kind = 'mcp'`, ag.ID)
	if err := d.ToggleVisibility(ag.ID, "mcp", mid, true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.ToggleSkillVisibility(ag.ID, "t-skill", true); err != nil {
		t.Fatal(err)
	}
	// agent-side read
	vm, _ := d.AgentVisible(ag.ID, "mcp")
	if len(vm) != 1 || vm[0] != mid {
		t.Fatalf("agent visible mcp: %+v", vm)
	}
	// resource-side read (same join row) → bidirectional
	ra, _ := d.ResourceAgents("mcp", mid)
	if len(ra) != 1 || ra[0] != ag.ID {
		t.Fatalf("resource agents: %+v", ra)
	}
	// toggle off
	d.ToggleVisibility(ag.ID, "mcp", mid, false)
	vm2, _ := d.AgentVisible(ag.ID, "mcp")
	if len(vm2) != 0 {
		t.Fatalf("after toggle off: %+v", vm2)
	}
	// skill visibility is name-keyed: verify the read, then deleting the skill's
	// visibility rows (called when a skill is removed) clears it.
	names, _ := d.AgentSkillNames(ag.ID)
	if len(names) != 1 || names[0] != "t-skill" {
		t.Fatalf("agent visible skills: %+v", names)
	}
	if err := d.DeleteSkillVisibility("t-skill"); err != nil {
		t.Fatal(err)
	}
	names2, _ := d.AgentSkillNames(ag.ID)
	if len(names2) != 0 {
		t.Fatalf("skill visibility should be cleared on delete: %+v", names2)
	}
	d.DeleteMCP(mid)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
