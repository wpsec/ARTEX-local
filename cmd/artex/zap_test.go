package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRedactingWriterRedactsSecretAcrossWrites(t *testing.T) {
	const secret = "plan-zap-fixture-key"
	var output bytes.Buffer
	writer := &redactingWriter{dst: &output, secret: secret}
	for _, part := range []string{"startup: ", secret[:7], secret[7:15], secret[15:], " loaded\n"} {
		if _, err := writer.Write([]byte(part)); err != nil {
			t.Fatalf("write log chunk: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush buffered log suffix: %v", err)
	}
	if got, want := output.String(), "startup: [REDACTED] loaded\n"; got != want {
		t.Fatalf("redacted log = %q, want %q", got, want)
	}
}

func TestWriteZAPConfigIsPrivate(t *testing.T) {
	path, err := writeZAPConfig("fixture-only-key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"mcp.enabled=true",
		"mcp.port=8282",
		"mcp.securityKeyEnabled=true",
		"mcp.securityKey=fixture-only-key",
		"mcp.secureOnly=false",
	} {
		if !strings.Contains(string(contents), expected) {
			t.Fatalf("ZAP config is missing required setting %q", expected)
		}
	}
}

func TestStartZAPRuntimeDisabledByDefault(t *testing.T) {
	t.Setenv("ARTEX_ZAP_ENABLED", "false")
	t.Setenv("ARTEX_MCP_SECRET_ZAP_KEY", "")

	runtime, err := startZAPRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatal("ZAP runtime started while disabled")
	}
}

func TestZAPSecretIsGeneratedWhenMissing(t *testing.T) {
	t.Setenv("ARTEX_ZAP_ENABLED", "true")
	t.Setenv("ARTEX_MCP_SECRET_ZAP_KEY", "")

	key, err := zapSecret()
	if err != nil {
		t.Fatalf("generate ZAP key: %v", err)
	}
	if len(key) != 43 {
		t.Fatalf("generated key length = %d, want 43", len(key))
	}
	if got := os.Getenv("ARTEX_MCP_SECRET_ZAP_KEY"); got != key {
		t.Fatal("generated key was not installed in the process environment")
	}
}
