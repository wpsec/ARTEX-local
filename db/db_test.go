package db

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type schemaExecFunc func(context.Context, string, ...any) (sql.Result, error)

func (f schemaExecFunc) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return f(ctx, query, args...)
}

func TestApplySchemaRetriesOnlyDeadlocks(t *testing.T) {
	deadlockAttempts := 0
	delays := []time.Duration{}
	err := applySchemaWithRetry(t.Context(), schemaExecFunc(func(context.Context, string, ...any) (sql.Result, error) {
		deadlockAttempts++
		if deadlockAttempts < 3 {
			return nil, &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
		}
		return nil, nil
	}), func(delay time.Duration) {
		delays = append(delays, delay)
	})
	if err != nil {
		t.Fatal(err)
	}
	if deadlockAttempts != 3 {
		t.Fatalf("schema attempts=%d, want 3", deadlockAttempts)
	}
	if len(delays) != 2 || delays[0] != schemaDeadlockRetryDelays[0] || delays[1] != schemaDeadlockRetryDelays[1] {
		t.Fatalf("schema retry delays=%v", delays)
	}

	nonRetryable := errors.New("permission denied")
	nonRetryableAttempts := 0
	err = applySchemaWithRetry(t.Context(), schemaExecFunc(func(context.Context, string, ...any) (sql.Result, error) {
		nonRetryableAttempts++
		return nil, nonRetryable
	}), func(time.Duration) {
		t.Fatal("non-deadlock error must not be retried")
	})
	if !errors.Is(err, nonRetryable) || nonRetryableAttempts != 1 {
		t.Fatalf("non-retryable result: attempts=%d err=%v", nonRetryableAttempts, err)
	}
}

func TestBuiltinSkillVisibilityDefaults(t *testing.T) {
	wantSkills := []string{
		"api-recon",
		"api-security-testing",
		"application-security-testing",
		"authorized-pentest-router",
		"conducting-internal-network-penetration-test",
		"find-security-vulnerabilities-in-code",
		"owasp-top-10-testing",
		"playwright-cli",
		"scopesentry",
		"web-app-penetration-testing",
	}
	if len(builtinSkillVisibility) != len(wantSkills) {
		t.Errorf("default Skill count=%d, want %d", len(builtinSkillVisibility), len(wantSkills))
	}
	for _, name := range wantSkills {
		got := builtinSkillVisibility[name]
		want := []string{"auto", "pentest", "worker"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s visibility=%v, want agents %v", name, got, want)
		}
	}
}

func TestSeedNewDeploymentRuntimeDefaults(t *testing.T) {
	sqlDB, err := sql.Open("pgx", testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := sqlDB.PingContext(t.Context()); err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}

	tx, err := sqlDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TEMP TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TEMP TABLE agents (key TEXT PRIMARY KEY, web_search BOOLEAN NOT NULL DEFAULT false)`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"planner", "worker", "mainagent", "auto", "pentest", "goals"} {
		if _, err := tx.Exec(`INSERT INTO agents(key) VALUES ($1)`, key); err != nil {
			t.Fatal(err)
		}
	}

	if err := seedNewDeploymentRuntimeDefaults(tx); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"traffic_capture",
		"agent_traffic_binding",
		"web_search_enabled",
		"constraints_inject_planner",
		"constraints_inject_worker",
	} {
		var value string
		if err := tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, key).Scan(&value); err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if value != "true" {
			t.Errorf("%s=%q, want true", key, value)
		}
	}
	var enabledAgents int
	if err := tx.QueryRow(`SELECT count(*) FROM agents WHERE web_search`).Scan(&enabledAgents); err != nil {
		t.Fatal(err)
	}
	if enabledAgents != 5 {
		t.Fatalf("web search enabled for %d agents, want 5 runtime agents", enabledAgents)
	}
}

// testDSN returns the configured DSN, skipping the test when neither the env var
// nor a config file supplies one (DSN no longer has a built-in default).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	return dsn
}

// TestOpenSeed opens the live dev PG, applies schema, seeds, and verifies the
// builtin agents + their variable catalog exist. Skips if PG is unreachable.
func TestOpenSeed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	wantAgents := len(builtinAgents)
	var agents int
	if err := d.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("want %d builtin agents, got %d", wantAgents, agents)
	}

	// planner should have at least its seeded catalog vars
	wantPlannerVars := 0
	for _, a := range builtinAgents {
		if a.key == "planner" {
			wantPlannerVars = len(a.vars)
			break
		}
	}
	var plannerVars int
	if err := d.QueryRow(`
SELECT count(*) FROM agent_prompt_vars v
JOIN agents a ON a.id = v.agent_id
WHERE a.key = 'planner'`).Scan(&plannerVars); err != nil {
		t.Fatal(err)
	}
	if plannerVars < wantPlannerVars {
		t.Fatalf("want at least %d planner vars, got %d", wantPlannerVars, plannerVars)
	}

	// re-open must be idempotent (no duplicate agents)
	d2, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if err := d2.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("after re-open want %d agents, got %d", wantAgents, agents)
	}
}
