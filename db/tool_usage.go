package db

import (
	"fmt"
	"strconv"
	"strings"
)

// ToolUsage is one catalog or MCP tool invocation. It stores attribution
// dimensions only; tool arguments and results are deliberately excluded.
type ToolUsage struct {
	ToolKey       string `json:"tool_key"`
	AgentKey      string `json:"agent_key"`
	TaskID        int64  `json:"task_id"`
	ExplorationID int64  `json:"exploration_id"`
	IntentID      int64  `json:"intent_id"`
	SessionID     string `json:"session_id"`
}

// InsertToolUsage appends one ledger row. Runtime callers treat metering as
// best-effort so a statistics failure never interrupts the tool itself.
func (d *DB) InsertToolUsage(u *ToolUsage) error {
	_, err := d.Exec(`
INSERT INTO tool_usage(tool_key, agent_key, task_id, exploration_id, intent_id, session_id)
VALUES ($1, NULLIF($2,''), $3, $4, $5, NULLIF($6,''))`,
		u.ToolKey, u.AgentKey, nullIfZero(u.TaskID), nullIfZero(u.ExplorationID),
		nullIfZero(u.IntentID), u.SessionID)
	return err
}

// ToolUsageCounts returns invocation totals keyed by tool key. Entries without
// calls are absent; archived task aggregates are included.
func (d *DB) ToolUsageCounts() (map[string]int, error) {
	rows, err := d.Query(`
SELECT tool_key, COUNT(*)
FROM tool_usage
GROUP BY tool_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var key string
		var calls int
		if err := rows.Scan(&key, &calls); err != nil {
			return nil, err
		}
		out[key] = calls
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	for _, aggregate := range archived {
		for key, calls := range aggregate.Tools {
			out[key] += calls
		}
	}
	return out, nil
}

// MCPToolUsageKey namespaces MCP tools by stable server ID to avoid collisions
// with catalog tools and with tools exposed by other MCP servers.
func MCPToolUsageKey(serverID int64, toolName string) string {
	return fmt.Sprintf("mcp:%d:%s", serverID, toolName)
}

func parseMCPToolUsageKey(key string) (int64, string, bool) {
	if !strings.HasPrefix(key, "mcp:") {
		return 0, "", false
	}
	serverIDText, toolName, ok := strings.Cut(strings.TrimPrefix(key, "mcp:"), ":")
	if !ok || toolName == "" {
		return 0, "", false
	}
	serverID, err := strconv.ParseInt(serverIDText, 10, 64)
	if err != nil || serverID <= 0 {
		return 0, "", false
	}
	return serverID, toolName, true
}

// MCPUsageCounts returns MCP invocation totals keyed by server ID. It includes
// archived task aggregates through ToolUsageCounts.
func (d *DB) MCPUsageCounts() (map[int64]int, error) {
	counts, err := d.ToolUsageCounts()
	if err != nil {
		return nil, err
	}
	out := map[int64]int{}
	for key, calls := range counts {
		serverID, _, ok := parseMCPToolUsageKey(key)
		if ok {
			out[serverID] += calls
		}
	}
	return out, nil
}

// MCPToolUsageCounts returns invocation totals for one MCP server, keyed by
// exposed tool name. It includes archived task aggregates.
func (d *DB) MCPToolUsageCounts(serverID int64) (map[string]int, error) {
	counts, err := d.ToolUsageCounts()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for key, calls := range counts {
		keyServerID, toolName, ok := parseMCPToolUsageKey(key)
		if ok && keyServerID == serverID {
			out[toolName] = calls
		}
	}
	return out, nil
}
