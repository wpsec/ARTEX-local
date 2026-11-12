package evidence

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/wpsec/ARTEX-local/db"
)

const (
	maxEvidenceQuoteCount = 16
	maxEvidenceQuoteRunes = 2048
	maxEvidenceBodyBytes  = 4 << 20
	maxEvidenceCheckBytes = 4 << 20
)

type quoteBodyResult struct {
	body []byte
	err  string
}

func (s *Store) checkEvidenceQuotes(ctx context.Context, quotes []db.FindingEvidenceQuote, bindings []db.FindingTrafficBinding) ([]db.FindingEvidenceQuote, string, string) {
	if len(quotes) == 0 {
		return []db.FindingEvidenceQuote{}, db.EvidenceCheckNotAssessed, "未提供结构化原文引用"
	}
	if len(bindings) == 0 {
		return append([]db.FindingEvidenceQuote(nil), quotes...), db.EvidenceCheckNotAssessed, "尚无绑定的 HTTP 证据"
	}
	if len(quotes) > maxEvidenceQuoteCount {
		return []db.FindingEvidenceQuote{}, db.EvidenceCheckNotAssessed, "引用数量超过核验上限"
	}
	bySnapshot := make(map[string]db.FindingTrafficBinding, len(bindings))
	byTraffic := make(map[string]db.FindingTrafficBinding, len(bindings))
	for _, binding := range bindings {
		bySnapshot[binding.SnapshotID] = binding
		if binding.Snapshot.SourceTrafficID != "" {
			byTraffic[binding.Snapshot.SourceTrafficID] = binding
		}
	}
	cache := make(map[string]quoteBodyResult)
	usedBytes := 0
	checked := append([]db.FindingEvidenceQuote(nil), quotes...)
	matched, unmatched, notAssessed := 0, 0, 0
	for i := range checked {
		if err := ctx.Err(); err != nil {
			return checked, db.EvidenceCheckNotAssessed, "证据核验已取消"
		}
		q := &checked[i]
		q.TrafficID = strings.TrimSpace(q.TrafficID)
		q.SnapshotID = strings.TrimSpace(q.SnapshotID)
		quoteRunes := utf8.RuneCountInString(q.Quote)
		if (q.Side != "request" && q.Side != "response") || strings.TrimSpace(q.Quote) == "" || quoteRunes < 8 || quoteRunes > maxEvidenceQuoteRunes {
			notAssessed++
			continue
		}
		binding, ok := bySnapshot[q.SnapshotID]
		if !ok && q.TrafficID != "" {
			binding, ok = byTraffic[q.TrafficID]
		}
		if !ok {
			unmatched++
			continue
		}
		q.TrafficID = binding.Snapshot.SourceTrafficID
		q.SnapshotID = binding.SnapshotID
		if binding.Role != "proof" && binding.Role != "verification" {
			notAssessed++
			continue
		}
		parsed, err := url.Parse(binding.Snapshot.URL)
		if err != nil || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
			notAssessed++
			continue
		}
		key := q.SnapshotID + ":" + q.Side
		body, exists := cache[key]
		if !exists {
			length := binding.Snapshot.RespLen
			if q.Side == "request" {
				length = binding.Snapshot.ReqLen
			}
			if length < 0 || length > maxEvidenceBodyBytes || usedBytes+int(length) > maxEvidenceCheckBytes {
				body.err = "正文超出核验大小上限"
			} else {
				var raw []byte
				raw, body.err = s.readQuoteBody(binding.Snapshot, q.Side)
				if body.err == "" && usedBytes+len(raw) > maxEvidenceCheckBytes {
					body.err = "累计核验正文超出大小上限"
				} else if body.err == "" {
					body.body = raw
					usedBytes += len(raw)
				}
			}
			cache[key] = body
		}
		if body.err != "" {
			notAssessed++
			continue
		}
		if bytes.Contains(body.body, []byte(q.Quote)) {
			matched++
		} else {
			unmatched++
		}
	}
	status := db.EvidenceCheckNotAssessed
	switch {
	case unmatched > 0:
		status = db.EvidenceCheckUnmatched
	case notAssessed == 0 && matched == len(checked):
		status = db.EvidenceCheckMatched
	}
	note := fmt.Sprintf("原文引用匹配 %d/%d，未匹配 %d，未核验 %d", matched, len(checked), unmatched, notAssessed)
	return checked, status, note
}

func (s *Store) readQuoteBody(snapshot db.TrafficEvidenceSnapshot, side string) ([]byte, string) {
	f, length, err := s.OpenBody(snapshot, side)
	if err != nil {
		return nil, err.Error()
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxEvidenceBodyBytes+1))
	if err != nil {
		return nil, err.Error()
	}
	if int64(len(raw)) != length || len(raw) > maxEvidenceBodyBytes {
		return nil, "正文长度不符或超出核验上限"
	}
	head := snapshot.RespHead
	if side == "request" {
		head = snapshot.ReqHead
	}
	encoding := headerValue(head, "Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return raw, ""
	}
	var reader io.ReadCloser
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(raw))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			reader = flate.NewReader(bytes.NewReader(raw))
			err = nil
		}
	default:
		return nil, "不支持的正文编码"
	}
	if err != nil {
		return nil, "压缩正文无法解码"
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxEvidenceBodyBytes+1))
	if err != nil {
		return nil, "压缩正文无法解码"
	}
	if len(decoded) > maxEvidenceBodyBytes {
		return nil, "解压正文超出核验上限"
	}
	return decoded, ""
}

func headerValue(block, name string) string {
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimSuffix(line, "\r")), ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Store) RecheckFindingEvidence(ctx context.Context, findingID int64) error {
	return s.UpdateFindingEvidence(ctx, findingID, nil, nil)
}

func (s *Store) UpdateFindingEvidence(ctx context.Context, findingID int64, quotes *[]db.FindingEvidenceQuote, counterevidence *string) error {
	finding, err := s.DB.GetFinding(findingID)
	if err != nil {
		return err
	}
	if finding == nil {
		return db.ErrFindingNotFound
	}
	currentQuotes := finding.EvidenceQuotes
	if quotes != nil {
		currentQuotes = *quotes
	}
	currentCounterevidence := finding.Counterevidence
	if counterevidence != nil {
		currentCounterevidence = *counterevidence
	}
	traffic, err := s.DB.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return err
	}
	checked, status, note := s.checkEvidenceQuotes(ctx, currentQuotes, traffic.Bindings)
	return s.DB.SetFindingEvidenceCheck(ctx, findingID, traffic.Version, checked, status, note, currentCounterevidence)
}
