package server

import (
	"context"
	"encoding/json"
	"log"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
)

type toolUsageRecorder interface {
	InsertToolUsage(*db.ToolUsage) error
}

// meteredTool records one row immediately before a catalog or MCP tool is
// invoked. It embeds the tool so schema, defaults and permission behavior remain
// unchanged.
type meteredTool struct {
	actool.CoreTool
	recorder toolUsageRecorder
	toolKey  string
	agentKey string
	ri       agent.RunInfo
}

func meterTool(t actool.CoreTool, recorder toolUsageRecorder, toolKey, agentKey string, ri agent.RunInfo) actool.CoreTool {
	if recorder == nil {
		return t
	}
	return &meteredTool{CoreTool: t, recorder: recorder, toolKey: toolKey, agentKey: agentKey, ri: ri}
}

func (m *meteredTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if err := m.recorder.InsertToolUsage(&db.ToolUsage{
		ToolKey:       m.toolKey,
		AgentKey:      m.agentKey,
		TaskID:        m.ri.TaskID,
		ExplorationID: m.ri.ExplorationID,
		IntentID:      m.ri.IntentID,
		SessionID:     m.ri.SessionID,
	}); err != nil {
		log.Printf("[toolusage] insert %s: %v", m.toolKey, err)
	}
	return m.CoreTool.Call(ctx, input, tc)
}
