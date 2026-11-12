package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/db"
)

type verificationCall struct {
	name  string
	input any
}

type verificationProvider struct {
	calls  []verificationCall
	system string
}

func (p *verificationProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.system = strings.Join(req.System, "\n")
	if len(p.calls) == 0 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("完成")}}, "end_turn", llm.Usage{}, nil
	}
	call := p.calls[0]
	p.calls = p.calls[1:]
	input, err := json.Marshal(call.input)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: fmt.Sprintf("call-%d", len(p.calls)), Name: call.name, Input: input}}}, "tool_use", llm.Usage{}, nil
}

func (p *verificationProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func TestPentestNativeChatAndFindingSchema(t *testing.T) {
	oldOverride := PromptOverride
	PromptOverride = func(key string) (string, bool) {
		prompt, ok := BuiltinPromptSeeds()[key]
		return prompt, ok
	}
	t.Cleanup(func() { PromptOverride = oldOverride })
	provider := &verificationProvider{}
	chat := NewChatAgent(provider, "fixture", t.TempDir(), nil, 0)
	chat.SetNonStreaming(func() bool { return true })
	if _, err := chat.Chat(t.Context(), "pentest", "fixture-session", "检查授权的本地目标", 8, time.Minute, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"候选漏洞与证据交接", "独立命令", "没有任务上下文"} {
		if !strings.Contains(provider.system, part) {
			t.Fatalf("native pentest chat missing %q", part)
		}
	}
	schema := NewToolSet(nil, "").addFinding().InputSchema()
	if _, ok := schema["properties"].(map[string]any)["evidence"]; !ok {
		t.Fatal("report_finding evidence field missing")
	}
	for _, field := range schema["required"].([]string) {
		if field == "evidence" {
			t.Fatal("report_finding evidence contract changed")
		}
	}
}

// The scripted provider exercises the native tool and graph plumbing; it does not
// measure whether a real model follows the verification instructions.
func TestVerificationWorkflowUsesNativeWorkerAndPlanner(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			task, err := d.CreateTask("verification fixture", "evaluate candidate", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
			as := d.Assets()
			assetID, err := as.UpsertApp(db.UpsertAppReq{Name: fmt.Sprintf("verification-%d-%d", task.ID, time.Now().UnixNano()), TaskID: task.ID})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = as.DeleteByIDs([]int64{assetID}) })
			ts := d.Exploration(task.ExplorationID)
			intentID, err := ts.AddIntent(map[string]any{"summary": "inspect candidate", "asset_ids": []int64{assetID}}, 5, []int64{assetID}, "planner")
			if err != nil {
				t.Fatal(err)
			}
			intent, err := ts.GetNode(intentID)
			if err != nil {
				t.Fatal(err)
			}
			first := &verificationProvider{calls: []verificationCall{{"record_fact", map[string]any{"summary": "候选待复核: fixture", "detail": "High; observed response", "confidence": "inferred", "intent_id": intentID, "asset_ids": []int64{assetID}}}}}
			worker := NewWorker(first, "fixture", t.TempDir(), nil, 0, 8)
			worker.SetNonStreaming(func() bool { return true })
			_, counts, err := worker.Execute(t.Context(), "first", task.ID, as, ts, intent, nil, nil, nil, nil)
			if err != nil || counts.Facts != 1 || counts.Findings != 0 || !strings.Contains(first.system, "候选漏洞复核与交接") {
				t.Fatalf("candidate run counts=%+v err=%v", counts, err)
			}
			facts, err := ts.ListByKind(db.KindFact, 100)
			if err != nil {
				t.Fatal(err)
			}
			var candidateID int64
			for _, f := range facts {
				if strings.Contains(string(f.Payload), "候选待复核") {
					candidateID = f.ID
				}
			}
			if candidateID == 0 {
				t.Fatal("candidate fact not recorded")
			}
			if err := ts.SetIntentState(intentID, "done"); err != nil {
				t.Fatal(err)
			}
			plannerProvider := &verificationProvider{calls: []verificationCall{{"add_intent", map[string]any{"summary": fmt.Sprintf("独立复核候选 fact %d", candidateID), "parent_ids": []int64{candidateID}, "asset_ids": []int64{assetID}}}}}
			planner := NewPlanner(plannerProvider, "fixture", t.TempDir(), nil, 0, 8)
			planner.SetNonStreaming(func() bool { return true })
			if _, _, err := planner.Plan(t.Context(), task.ID, as, ts, "evaluate candidate", nil, nil); err != nil || !strings.Contains(plannerProvider.system, "候选漏洞复核") {
				t.Fatalf("planner err=%v", err)
			}
			intents, err := ts.ListByKind(db.KindIntent, 100)
			if err != nil {
				t.Fatal(err)
			}
			var verification *db.Node
			for _, node := range intents {
				if node.ID != intentID {
					verification = node
				}
			}
			if verification == nil {
				t.Fatal("verification intent missing")
			}
			var anchorCount int
			if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, verification.ID, assetID).Scan(&anchorCount); err != nil || anchorCount != 1 {
				t.Fatalf("verification intent lost asset: count=%d err=%v", anchorCount, err)
			}
			edges, err := ts.Edges(100)
			if err != nil {
				t.Fatal(err)
			}
			linked := false
			for _, edge := range edges {
				linked = linked || (edge.From == candidateID && edge.To == verification.ID && edge.Rel == db.RelDerivedFrom)
			}
			if !linked {
				t.Fatal("verification intent lost candidate lineage")
			}
			calls := []verificationCall{{"node_detail", map[string]any{"id": candidateID}}}
			if verified {
				calls = append(calls, verificationCall{"report_finding", map[string]any{"vulnclass": "fixture", "severity": "high", "summary": "verified fixture", "evidence": fmt.Sprintf("candidate fact %d: trigger, observed result, independent verification", candidateID), "intent_id": verification.ID, "asset_ids": []int64{assetID}}})
			} else {
				calls = append(calls, verificationCall{"record_fact", map[string]any{"summary": fmt.Sprintf("候选复核未确认 fact %d", candidateID), "detail": "independent check failed", "intent_id": verification.ID, "asset_ids": []int64{assetID}}})
			}
			verifyProvider := &verificationProvider{calls: calls}
			verifier := NewWorker(verifyProvider, "fixture", t.TempDir(), nil, 0, 8)
			verifier.SetNonStreaming(func() bool { return true })
			_, counts, err = verifier.Execute(t.Context(), "second", task.ID, as, ts, verification, nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := ts.ListByKind(db.KindFinding, 100)
			if err != nil || (verified && (len(findings) != 1 || counts.Findings != 1 || !strings.Contains(string(findings[0].Payload), "independent verification"))) || (!verified && (len(findings) != 0 || counts.Facts != 1)) {
				t.Fatalf("verified=%v findings=%+v counts=%+v err=%v", verified, findings, counts, err)
			}
			if !verified {
				result := callReadJSON(t, NewToolSet(ts, "planner").listFacts(), fmt.Sprintf(`{"q":"fact %d"}`, candidateID))
				if !strings.Contains(fmt.Sprint(result), "候选复核未确认") {
					t.Fatalf("verification result not searchable by candidate: %v", result)
				}
			}
		})
	}
}
