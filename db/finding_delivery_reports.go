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
