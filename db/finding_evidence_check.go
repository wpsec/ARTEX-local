package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func ValidEvidenceCheckStatus(status string) bool {
	switch status {
	case EvidenceCheckMatched, EvidenceCheckUnmatched, EvidenceCheckNotAssessed:
		return true
	default:
		return false
	}
}

// SetFindingEvidenceCheck saves the bounded quote check against the evidence
// version observed by the caller. It never changes the finding's triage state.
func (d *DB) SetFindingEvidenceCheck(ctx context.Context, findingID, version int64, quotes []FindingEvidenceQuote, status, note, counterevidence string) error {
	if !ValidEvidenceCheckStatus(status) {
		return errors.New("invalid evidence check status")
	}
	if quotes == nil {
		quotes = []FindingEvidenceQuote{}
	}
	raw, err := json.Marshal(quotes)
	if err != nil {
		return err
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		var nodeID sql.NullInt64
		if err := tx.QueryRow(`UPDATE findings SET evidence_check_status=$2,evidence_check_note=$3,
evidence_quotes=$4::jsonb,counterevidence=$5 WHERE id=$1 RETURNING node_id`,
			findingID, status, note, string(raw), counterevidence).Scan(&nodeID); err != nil {
			return err
		}
		if nodeID.Valid {
			_, err = tx.Exec(`UPDATE exploration_nodes SET payload=payload || jsonb_build_object(
'evidence_check_status',$2,'evidence_check_note',$3,'evidence_quotes',$4::jsonb,'counterevidence',$5)
WHERE id=$1`, nodeID.Int64, status, note, string(raw), counterevidence)
		}
		return err
	})
}
