package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noa"
)

func TestEnableNoaDisabledKeepsNativeCompaction(t *testing.T) {
	workDir := t.TempDir()
	opts := &agentcore.Options{Compaction: compactionConfig(8192)}

	enableNoa(opts, func() bool { return false }, workDir, "exp1-planner", nil)

	if opts.Compaction == nil || opts.Compactor != nil {
		t.Fatal("disabled noa must leave native compaction enabled")
	}
	if _, err := os.Stat(filepath.Join(workDir, "noa")); !os.IsNotExist(err) {
		t.Fatalf("disabled noa created its archive directory: stat err=%v", err)
	}
}

func TestEnableNoaUsesPrivatePersistentArchiveRoot(t *testing.T) {
	workDir := t.TempDir()
	archiveDir := filepath.Join(workDir, "noa")
	if err := os.Mkdir(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := &agentcore.Options{
		SystemPrompt:    []string{"system", "deferred tools"},
		DynamicBoundary: 2,
		Compaction:      compactionConfig(8192),
	}

	enableNoa(opts, func() bool { return true }, workDir, "exp1-planner", nil)

	if opts.Compactor == nil || opts.Compaction != nil {
		t.Fatal("enabled noa must replace native compaction with its compactor")
	}
	if len(opts.Tools) != 1 || opts.Tools[0].Name() != noa.CompressToolName {
		t.Fatalf("enabled noa must attach its Compress tool, got %v", opts.Tools)
	}
	if len(opts.AppendSystemPrompt) != 1 || !strings.Contains(opts.AppendSystemPrompt[0], "noa context management") {
		t.Fatalf("enabled noa must attach its system guidance, got %v", opts.AppendSystemPrompt)
	}
	if opts.DynamicBoundary != len(opts.SystemPrompt)+len(opts.AppendSystemPrompt) {
		t.Fatalf("DynamicBoundary=%d, want it to cover the static noa prompt", opts.DynamicBoundary)
	}

	info, err := os.Stat(archiveDir)
	if err != nil {
		t.Fatalf("stat archive directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("archive directory mode=%#o, want 0700", got)
	}
}

func TestEnableNoaSetupFailureKeepsNativeCompaction(t *testing.T) {
	workDir := t.TempDir()
	blocker := filepath.Join(workDir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &agentcore.Options{Compaction: compactionConfig(8192)}
	var warning string

	enableNoa(opts, func() bool { return true }, blocker, "exp1-planner", func(message string) {
		warning = message
	})

	if opts.Compaction == nil || opts.Compactor != nil || len(opts.Tools) != 0 || len(opts.AppendSystemPrompt) != 0 {
		t.Fatal("failed noa setup must preserve the original options")
	}
	if !strings.Contains(warning, "回退内置压缩") {
		t.Fatalf("warning=%q, want fallback diagnostic", warning)
	}
}
