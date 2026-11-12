package server

import (
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func TestBundledCoreSkillsLoad(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("load bundled skills: %v", err)
	}

	want := []string{
		"api-recon",
		"api-security-testing",
		"application-security-testing",
		"authorized-pentest-router",
		"conducting-internal-network-penetration-test",
		"find-security-vulnerabilities-in-code",
		"owasp-top-10-testing",
		"playwright-cli",
		"scopesentry-mcp",
		"web-app-penetration-testing",
	}
	for _, name := range want {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("bundled core skill %q was not loaded", name)
		}
	}
	if got := len(reg.List()); got != len(want) {
		t.Errorf("bundled Skill count=%d, want %d", got, len(want))
	}
}
