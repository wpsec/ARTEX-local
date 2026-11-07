package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpsec/ARTEX-local/db"
)

func TestNormalizeCVSS4BaseVector(t *testing.T) {
	valid := []string{
		"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
	}
	for _, vector := range valid {
		got, ok := normalizeCVSS4BaseVector(vector)
		if !ok || got != vector {
			t.Errorf("normalizeCVSS4BaseVector(%q) = (%q, %v), want unchanged valid vector", vector, got, ok)
		}
	}
	invalid := []string{
		"AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
	}
	for _, vector := range invalid {
		if got, ok := normalizeCVSS4BaseVector(vector); ok {
			t.Errorf("normalizeCVSS4BaseVector(%q) = (%q, true), want rejection", vector, got)
		}
	}
}

func TestDeliveryReportWithoutBoundTrafficDoesNotInventPackets(t *testing.T) {
	request, response, err := (&Server{}).deliveryTrafficPackets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if request != missingTrafficPacket || response != missingTrafficPacket {
		t.Fatalf("missing traffic placeholders = (%q, %q)", request, response)
	}
}

func TestDeliveryReportUsesProofPacketAndPreservesCredentials(t *testing.T) {
	dataDir := t.TempDir()
	managerDir := filepath.Join(dataDir, "manager")
	storeDir := filepath.Join(managerDir, "evidence")
	writeBody := func(body string) (string, int64) {
		t.Helper()
		raw := []byte(body)
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		path := filepath.Join(storeDir, "blobs", hash[:2], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return hash, int64(len(raw))
	}
	baselineRequestHash, baselineRequestLen := writeBody(`{"value":"baseline request"}`)
	baselineResponseHash, baselineResponseLen := writeBody(`{"value":"baseline response"}`)
	proofRequestHash, proofRequestLen := writeBody(`{"password":"body-secret","value":"proof request"}`)
	proofResponseHash, proofResponseLen := writeBody(`{"token":"response-secret","value":"proof response"}`)
	baseline := db.TrafficEvidenceSnapshot{
		ReqHead: "POST /baseline HTTP/1.1\r\nHost: baseline.test", RespHead: "HTTP/1.1 200 OK",
		ReqHash: baselineRequestHash, ReqLen: baselineRequestLen, RespHash: baselineResponseHash, RespLen: baselineResponseLen,
	}
	proof := db.TrafficEvidenceSnapshot{
		ReqHead:  "POST /proof?access_token=query-secret HTTP/1.1\r\nHost: proof.test\r\nAuthorization: Bearer header-secret\r\nCookie: session=cookie-secret",
		RespHead: "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-cookie",
		ReqHash:  proofRequestHash, ReqLen: proofRequestLen, RespHash: proofResponseHash, RespLen: proofResponseLen,
	}
	s := &Server{m: &Manager{dir: managerDir}}
	request, response, err := s.deliveryTrafficPackets([]db.FindingTrafficBinding{
		{Role: "baseline", Snapshot: baseline},
		{Role: "proof", Snapshot: proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ packet, want, absent string }{
		{request, "POST /proof", "baseline"},
		{request, "proof request", "baseline request"},
		{response, "proof response", "baseline response"},
	} {
		if !strings.Contains(check.packet, check.want) || strings.Contains(check.packet, check.absent) {
			t.Fatalf("packet did not use the bound proof evidence: %s", check.packet)
		}
	}
	for _, secret := range []string{"query-secret", "header-secret", "session=cookie-secret", "body-secret", "response-cookie", "response-secret"} {
		if !strings.Contains(request+response, secret) {
			t.Fatalf("delivery packet omitted original credential %q: %s\n%s", secret, request, response)
		}
	}
}

func TestFindingDeliveryReportIsolationAndEvidenceVersion(t *testing.T) {
	s, finding, request := trafficEvidenceServer(t)
	findingRecord, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if findingRecord == nil || findingRecord.TaskID == nil {
		t.Fatal("fixture finding has no owning task")
	}
	ownerID := *findingRecord.TaskID
	child, err := s.m.CreateTaskWithOptions("delivery child", "independent report", db.TaskCreateOptions{SourceTaskIDs: []int64{ownerID}})
	if err != nil {
		t.Fatal(err)
	}
	childID := mustTaskID(t, child.ID)
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(childID) })
	outsider, err := s.m.CreateTask("delivery outsider", "no inherited finding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	outsiderID := mustTaskID(t, outsider.ID)
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(outsiderID) })

	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	put := func(taskID int64, content, cvss string, version int64) int {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"content": content, "cvss_vector": cvss, "evidence_version": version,
		})
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", taskID, finding.FindingID)
		return request(http.MethodPut, path, string(body)).Code
	}
	get := func(taskID int64) FindingDeliveryReport {
		t.Helper()
		path := fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", taskID, finding.FindingID)
		w := request(http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("get delivery report: status=%d body=%s", w.Code, w.Body.String())
		}
		var report FindingDeliveryReport
		if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}

	if code := put(ownerID, "owner report", vector, 0); code != http.StatusOK {
		t.Fatalf("save owner report: status=%d", code)
	}
	if code := put(childID, "child report", vector, 0); code != http.StatusOK {
		t.Fatalf("save inherited report: status=%d", code)
	}
	if owner := get(ownerID); owner.Content != "owner report" || !owner.Exists {
		t.Fatalf("owner report was not persisted independently: %+v", owner)
	}
	if inherited := get(childID); inherited.Content != "child report" || !inherited.Exists {
		t.Fatalf("inherited report was not persisted independently: %+v", inherited)
	}
	if w := request(http.MethodGet, fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", outsiderID, finding.FindingID), ""); w.Code != http.StatusNotFound {
		t.Fatalf("unrelated task accessed finding report: status=%d body=%s", w.Code, w.Body.String())
	}

	if code := put(ownerID, "invalid overwrite", "CVSS:4.0/AV:N", 0); code != http.StatusBadRequest {
		t.Fatalf("invalid vector save status=%d", code)
	}
	if got := get(ownerID); got.Content != "owner report" {
		t.Fatalf("invalid vector overwrote saved report: %+v", got)
	}

	seedTraffic := func(id, path, requestHead, requestBody, responseBody string) {
		t.Helper()
		_, err := s.m.traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,1,'delivery.local','POST',?,?,200,'application/json',?,?,'')`,
			id, path, "http://delivery.local"+path, len(requestBody), len(responseBody))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.m.traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body)
VALUES(?,?,'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=response-cookie',?,?)`,
			id, requestHead, []byte(requestBody), []byte(responseBody))
		if err != nil {
			t.Fatal(err)
		}
	}
	seedTraffic("delivery-report-baseline", "/baseline", "POST /baseline HTTP/1.1\r\nHost: delivery.local", `{"value":"baseline"}`, `{"value":"baseline response"}`)
	seedTraffic("delivery-report-proof", "/proof?access_token=query-secret", "POST /proof?access_token=query-secret HTTP/1.1\r\nHost: delivery.local\r\nAuthorization: Bearer header-secret\r\nCookie: sid=request-cookie", `{"password":"body-secret","value":"proof request"}`, `{"token":"response-secret","value":"proof response"}`)
	if _, err := s.evidenceStore().Bind(context.Background(), finding.FindingID, []db.TrafficRef{
		{TrafficID: "delivery-report-baseline", Role: "baseline"},
		{TrafficID: "delivery-report-proof", Role: "proof"},
	}); err != nil {
		t.Fatal(err)
	}
	traffic, err := s.m.pg.GetFindingTraffic(context.Background(), finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	requestPacket, responsePacket, err := s.deliveryTrafficPackets(traffic.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ packet, want, absent string }{
		{requestPacket, "POST /proof", "baseline"},
		{responsePacket, "proof response", "baseline response"},
	} {
		if !strings.Contains(check.packet, check.want) || strings.Contains(check.packet, check.absent) {
			t.Fatalf("delivery packet did not select bound proof traffic: %s", check.packet)
		}
	}
	for _, secret := range []string{"query-secret", "header-secret", "request-cookie", "body-secret", "response-cookie", "response-secret"} {
		if strings.Contains(requestPacket+responsePacket, secret) {
			t.Fatalf("delivery packet leaked %q", secret)
		}
	}
	if code := put(ownerID, "stale overwrite", vector, 0); code != http.StatusConflict {
		t.Fatalf("stale report save status=%d", code)
	}
	stale := get(ownerID)
	if stale.Content != "owner report" || stale.EvidenceVersion != 0 || stale.CurrentEvidenceVersion != 1 {
		t.Fatalf("stale evidence changed saved report or version state: %+v", stale)
	}
}

type FindingDeliveryReport struct {
	Content                string `json:"content"`
	EvidenceVersion        int64  `json:"evidence_version"`
	CurrentEvidenceVersion int64  `json:"current_evidence_version"`
	Exists                 bool   `json:"exists"`
}
