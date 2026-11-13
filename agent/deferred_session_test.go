package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSkillGatedMCPCallThroughSession(t *testing.T) {
	const (
		mcpToolName = "mcp__zap__version"
		skillName   = "web-app-penetration-testing"
	)
	var calls atomic.Int32
	mcpTool := actool.Build(actool.Spec{
		Name:        mcpToolName,
		Description: "Return the fixture ZAP version.",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			calls.Add(1)
			return actool.Text("ZAP fixture 2.17.0"), nil
		},
	})

	unlock := actool.NewUnlockSet()
	reg := skill.NewRegistry(skill.Skill{
		Name:         skillName,
		Description:  "Use ZAP for authorized Web tests.",
		Instructions: "Use the fixture MCP tool only.",
		MCPs:         []string{"OWASP ZAP"},
	})
	unlockSkill := func(name string) {
		s, ok := reg.Get(name)
		if !ok {
			return
		}
		for _, server := range s.MCPs {
			if server == "OWASP ZAP" {
				unlock.Add(mcpToolName)
			}
		}
	}
	reg.OnInvoke = func(s skill.Skill) string {
		if s.Name != skillName || len(s.MCPs) != 1 || s.MCPs[0] != "OWASP ZAP" {
			return ""
		}
		unlockSkill(s.Name)
		return actool.RenderDeferredToolsBlock([]string{mcpToolName})
	}

	previousAugment := ToolAugment
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		return []actool.CoreTool{mcpTool, reg.Tool()}, DeferredInfo{
			Deferred:    []string{mcpToolName},
			Unlock:      unlock,
			UnlockSkill: unlockSkill,
		}, func() {}
	}
	t.Cleanup(func() { ToolAugment = previousAugment })
	tools, def, cleanup := AugmentTools(context.Background(), "mainagent", nil)
	t.Cleanup(cleanup)

	turns := [][]llm.StreamEvent{
		deferredTestToolTurn(actool.ExecuteExtraToolName, `{"tool_name":"`+mcpToolName+`","params":{}}`),
		deferredTestToolTurn("Skill", `{"name":"`+skillName+`"}`),
		deferredTestToolTurn(actool.SearchExtraToolsName, `{"query":"select:`+mcpToolName+`"}`),
		deferredTestToolTurn(actool.ExecuteExtraToolName, `{"tool_name":"`+mcpToolName+`","params":{}}`),
		deferredTestTextTurn("done"),
	}
	var sawInitialSchema, sawRevealedName, sawSearchedSchema bool
	var turnIndex int
	deps := harness.QueryDeps{CallModel: func(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		idx := turnIndex
		turnIndex++
		return func(yield func(llm.StreamEvent, error) bool) {
			if idx >= len(turns) {
				yield(llm.StreamEvent{}, fmt.Errorf("unexpected model turn %d", idx))
				return
			}
			if idx == 0 {
				hasSkill, hasSearch, hasExecute, hasMCP := false, false, false, false
				for _, schema := range req.Tools {
					switch schema.Name {
					case "Skill":
						hasSkill = true
					case actool.SearchExtraToolsName:
						hasSearch = true
					case actool.ExecuteExtraToolName:
						hasExecute = true
					case mcpToolName:
						hasMCP = true
					}
				}
				sawInitialSchema = hasSkill && hasSearch && hasExecute && !hasMCP
			}
			if idx == 2 || idx == 3 {
				messages, err := json.Marshal(req.Messages)
				if err != nil {
					yield(llm.StreamEvent{}, err)
					return
				}
				sawRevealedName = sawRevealedName || strings.Contains(string(messages), mcpToolName)
				if idx == 3 {
					sawSearchedSchema = strings.Contains(string(messages), "params schema")
				}
			}
			for _, event := range turns[idx] {
				if !yield(event, nil) {
					return
				}
			}
		}
	}}

	system, boundary := deferredSystem("test", def)
	session := agentcore.NewSession(agentcore.Options{
		SystemPrompt:           system,
		DynamicBoundary:        boundary,
		Tools:                  tools,
		DeferredTools:          def.Deferred,
		UnlockSet:              def.Unlock,
		PermissionMode:         permission.ModeBypass,
		DisableBackgroundTasks: true,
		Deps:                   deps,
	})
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("close session: %v", err)
		}
	})

	var locked, searched, called bool
	for event, err := range session.Prompt(context.Background(), "load the Web test skill and inspect ZAP") {
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind != harness.KindToolResult || event.ToolResult == nil {
			continue
		}
		result := event.ToolResult
		text := ""
		for _, block := range result.Content {
			text += block.Text
		}
		if result.IsError && strings.Contains(text, "not unlocked") {
			locked = true
		}
		if !result.IsError && strings.Contains(text, mcpToolName) && strings.Contains(text, "params schema") {
			searched = true
		}
		if !result.IsError && strings.Contains(text, "ZAP fixture 2.17.0") {
			called = true
		}
	}

	if !sawInitialSchema {
		t.Fatal("deferred MCP schema was not hidden while Skill and deferred-access tools were available")
	}
	if !locked {
		t.Fatal("deferred MCP call before Skill load was not rejected")
	}
	if !sawRevealedName || !sawSearchedSchema || !searched {
		t.Fatal("Skill load did not reveal the MCP name and SearchExtraTools schema")
	}
	if !called || calls.Load() != 1 {
		t.Fatalf("unlocked MCP call did not reach the tool exactly once (result=%v calls=%d)", called, calls.Load())
	}
}

func deferredTestToolTurn(name, input string) []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SEToolUseStart, ToolID: "deferred-test", ToolName: name},
		{Type: llm.SEToolInputJSON, Text: input},
		{Type: llm.SEMessageDelta, StopReason: "tool_use"},
		{Type: llm.SEMessageStop},
	}
}

func deferredTestTextTurn(text string) []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: text},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
		{Type: llm.SEMessageStop},
	}
}
