package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type FindingDeliveryReport struct {
	TaskID                 int64      `json:"task_id,string"`
	FindingID              int64      `json:"finding_id,string"`
	Content                string     `json:"content"`
	CVSSVector             string     `json:"cvss_vector"`
	EvidenceVersion        int64      `json:"evidence_version"`
	CurrentEvidenceVersion int64      `json:"current_evidence_version"`
	Exists                 bool       `json:"exists"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
}

type IncompleteFindingReport struct {
	TaskID          int64
	FindingID       int64
	NodeID          int64
	TaskDescription string
	TaskGoal        string
}

// FindingsMissingReportsBefore returns task findings whose detailed and delivery
// reports are both absent and whose reporter conversation existed before the
// recovery boundary. This avoids treating older findings that were never sent to
// the reporter as interrupted work or overwriting a partially present report.
func (d *DB) FindingsMissingReportsBefore(before time.Time) ([]IncompleteFindingReport, error) {
	rows, err := d.Query(`
SELECT f.task_id, f.id, f.node_id, t.description, t.goal
FROM findings f
JOIN tasks t ON t.id=f.task_id AND t.deleted_at IS NULL
LEFT JOIN finding_delivery_reports r ON r.task_id=f.task_id AND r.finding_id=f.id
WHERE f.node_id IS NOT NULL AND f.created_at < $1
  AND NULLIF(btrim(COALESCE(f.report,'')), '') IS NULL
  AND NULLIF(btrim(COALESCE(r.content,'')), '') IS NULL
  AND EXISTS (
      SELECT 1
      FROM conversations c
      JOIN conversation_activities ca ON ca.conversation_id=c.id
      WHERE c.agent_key='reporter' AND c.created_at < $1 AND ca.kind='user'
        AND position(('finding recorded: ' || f.node_id::text || E'\n') in COALESCE(ca.detail,'')) > 0
  )
ORDER BY f.created_at, f.id`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]IncompleteFindingReport, 0)
	for rows.Next() {
		var finding IncompleteFindingReport
		if err := rows.Scan(&finding.TaskID, &finding.FindingID, &finding.NodeID,
			&finding.TaskDescription, &finding.TaskGoal); err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingDeliveryReport(taskID, findingID int64) (*FindingDeliveryReport, error) {
	out := &FindingDeliveryReport{TaskID: taskID, FindingID: findingID}
	var updatedAt sql.NullTime
	err := d.QueryRow(`SELECT f.evidence_version,
       COALESCE(r.content,''), COALESCE(r.cvss_vector,''),
       COALESCE(r.evidence_version,0), r.updated_at
FROM findings f
LEFT JOIN finding_delivery_reports r ON r.finding_id=f.id AND r.task_id=$1
WHERE f.id=$2`, taskID, findingID).Scan(
		&out.CurrentEvidenceVersion, &out.Content, &out.CVSSVector, &out.EvidenceVersion, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.Exists = updatedAt.Valid
	if updatedAt.Valid {
		out.UpdatedAt = &updatedAt.Time
	}
	return out, nil
}

func (d *DB) SaveFindingDeliveryReport(ctx context.Context, taskID, findingID, evidenceVersion int64, content, vector string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := LockTaskEvidenceTx(tx, taskID); err != nil {
		return err
	}
	if err := LockFindingEvidenceTx(tx, findingID, &evidenceVersion); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_delivery_reports
(task_id,finding_id,content,cvss_vector,evidence_version)
VALUES($1,$2,$3,$4,$5)
ON CONFLICT(task_id,finding_id) DO UPDATE SET
content=EXCLUDED.content, cvss_vector=EXCLUDED.cvss_vector,
evidence_version=EXCLUDED.evidence_version, updated_at=now()`,
		taskID, findingID, content, vector, evidenceVersion); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) SetFindingReportsByNodeID(ctx context.Context, nodeID int64, report, deliveryReport, vector string, evidenceVersion int64) (n int64, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var findingID int64
		var taskID sql.NullInt64
		if err := tx.QueryRow(`SELECT id,task_id FROM findings WHERE node_id=$1`, nodeID).Scan(&findingID, &taskID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if !taskID.Valid {
			return errors.New("漏洞没有任务归属，无法保存交付报告")
		}
		if err := LockFindingEvidenceTx(tx, findingID, &evidenceVersion); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE findings SET report=$2,report_evidence_version=$3 WHERE id=$1`, findingID, report, evidenceVersion)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO finding_delivery_reports
	(task_id,finding_id,content,cvss_vector,evidence_version)
VALUES($1,$2,$3,$4,$5)
ON CONFLICT(task_id,finding_id) DO UPDATE SET
	content=EXCLUDED.content, cvss_vector=EXCLUDED.cvss_vector,
	evidence_version=EXCLUDED.evidence_version, updated_at=now()`,
			taskID.Int64, findingID, deliveryReport, vector, evidenceVersion)
		return err
	})
	return n, err
}
