package server

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

func TestVerificationPromptUpgradePreservesCustomizedAgents(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Skip("test database needs a PostgreSQL URL")
	}
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("artex_agent_prompt_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Skipf("cannot create isolated database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Errorf("drop isolated database: %v", err)
		}
	})
	testURL := *u
	testURL.Path = "/" + name
	pg, err := db.Open(testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	previous := agent.PreviousVerificationPromptSeeds()
	for key, prompt := range previous {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			t.Fatalf("agent %s: %v", key, err)
		}
		if _, err := pg.SavePrompt(a.ID, prompt, "old default", "system"); err != nil {
			t.Fatal(err)
		}
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker agent: %v", err)
	}
	if _, err := pg.SavePrompt(worker.ID, "user customized worker", "user", "user"); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: pg}}
	s.upgradeVerificationPrompts()
	s.upgradeVerificationPrompts()
	for key := range previous {
		a, err := pg.GetAgentByKey(key)
		if err != nil {
			t.Fatal(err)
		}
		current, err := pg.CurrentPrompt(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := agent.BuiltinPromptSeeds()[key]
		if key == "worker" {
			want = "user customized worker"
		}
		versions, err := pg.ListPromptVersions(a.ID)
		if err != nil || current != want || len(versions) != 2 || versions[1].Template != previous[key] {
			t.Fatalf("%s current/history unexpected: versions=%d err=%v", key, len(versions), err)
		}
	}
}
