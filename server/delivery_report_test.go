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
	"github.com/wpsec/ARTEX-local/evidence"
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

func TestDeliveryReportUsesAllBoundPacketsWithoutRedactingCredentials(t *testing.T) {
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
	for _, check := range []struct{ packet, want string }{
		{request, "POST /proof"},
		{request, "baseline request"},
		{request, "proof request"},
		{response, "baseline response"},
		{response, "proof response"},
	} {
		if !strings.Contains(check.packet, check.want) {
			t.Fatalf("packet did not use the bound proof evidence: %s", check.packet)
		}
	}
	for _, evidence := range []struct{ packet, want string }{
		{request, "access_token=query-secret"},
		{request, "Authorization: Bearer header-secret"},
		{request, "Cookie: session=cookie-secret"},
		{request, `"password":"body-secret"`},
		{response, "Set-Cookie: session=response-cookie"},
		{response, `"token":"response-secret"`},
	} {
		if !strings.Contains(evidence.packet, evidence.want) {
			t.Fatalf("delivery packet omitted original evidence %q: %s\n%s", evidence.want, request, response)
		}
	}
}

func TestDeliveryTrafficEvidencePairsSeparatePacketsWithinEvidenceSection(t *testing.T) {
	store := evidence.New(nil, nil, t.TempDir())
	baseline := deliveryPacketFixture(t, store, "GET /before HTTP/1.1\r\nHost: report.test", "", "HTTP 200\nContent-Type: application/json", `{"count":2}`)
	baseline.SourceTrafficID = "baseline-source"
	baseline.URL = "https://report.test/before"
	baseline.CapturedAt = 1700000000
	proof := deliveryPacketFixture(t, store, "POST /write HTTP/1.1\r\nHost: report.test", `{"value":"proof"}`, "HTTP/1.1 200 OK", `{"id":3}`)
	proof.SourceTrafficID = "proof-source"
	proof.URL = "https://report.test/write"
	proof.CapturedAt = 1700000001
	appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{
		{ID: 11, Role: "baseline", Note: "写入前读取记录数", Snapshot: baseline},
		{ID: 12, Role: "proof", Note: "验证写入结果\n## 不能变成章节", Snapshot: proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(appendix, "\n## ") || strings.Count(appendix, "```http\n") != 4 {
		t.Fatalf("evidence changed the report's section structure or combined packets: %s", appendix)
	}
	for _, want := range []string{"2023-11-15T06:13:20+08:00", "baseline-source", "proof-source", "写入前读取记录数", "头部由平台采集时整理", "HTTP 200\nContent-Type: application/json"} {
		if !strings.Contains(appendix, want) {
			t.Errorf("evidence omitted provenance or stored bytes %q", want)
		}
	}
	last := -1
	for _, want := range []string{"#### 证据绑定 11", "GET /before HTTP/1.1", `{"count":2}`, "#### 证据绑定 12", "POST /write HTTP/1.1", `{"id":3}`} {
		index := strings.Index(appendix, want)
		if index <= last {
			t.Fatalf("request and response did not remain paired at %q: %s", want, appendix)
		}
		last = index
	}
	for _, chunk := range strings.Split(appendix, "```http\n")[1:] {
		packet, _, found := strings.Cut(chunk, "\n```")
		if !found || strings.Contains(packet, "证据绑定") || strings.Contains(packet, "源流量编号") {
			t.Fatalf("an HTTP block includes report labels: %s", packet)
		}
	}
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	report := deliveryReportFixture("测试结论", vector) + "\n\n" + deliveryEvidenceAppendixMarker + "\n" + appendix
	if err := validateDeliveryReportTemplate(report, vector); err != nil {
		t.Fatalf("evidence appendix broke the five-section template: %v", err)
	}
	if got := stripDeliveryTrafficEvidence(report); got != deliveryReportFixture("测试结论", vector) {
		t.Fatalf("automatic evidence was not removable before regeneration: %s", got)
	}
}

func TestDeliveryTrafficEvidenceMarksMissingAndBinaryMaterial(t *testing.T) {
	store := evidence.New(nil, nil, t.TempDir())
	snapshot := deliveryPacketFixture(t, store, "", string([]byte{0, 255, 1}), "HTTP 200", "ok")
	appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{{ID: 7, Role: "proof", Snapshot: snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"采集时间：未留存", "源流量编号：未留存", "报文头未留存", "Base64", "AP8B", "不能直接粘贴重放", "HTTP 200"} {
		if !strings.Contains(appendix, want) {
			t.Errorf("evidence omitted the limitation %q: %s", want, appendix)
		}
	}
	if strings.Contains(appendix, "HTTP/1.1 200") {
		t.Fatal("renderer invented a response protocol version")
	}
	missing, err := renderDeliveryTrafficEvidence(nil, nil)
	if err != nil || !strings.Contains(missing, "未绑定 ARTEX HTTP 流量") || strings.Contains(missing, "\n## ") {
		t.Fatalf("missing traffic was not reported inside the existing section: %q, %v", missing, err)
	}
}

func TestDeliveryTrafficEvidenceRejectsOversizeOrDamagedBodies(t *testing.T) {
	if appendix, err := renderDeliveryTrafficEvidence(nil, []db.FindingTrafficBinding{{Snapshot: db.TrafficEvidenceSnapshot{ReqLen: deliveryReportEvidenceMaxBytes + 1}}}); err == nil || appendix != "" {
		t.Fatalf("oversize evidence was rendered: %q, %v", appendix, err)
	}
	store := evidence.New(nil, nil, t.TempDir())
	snapshot := deliveryPacketFixture(t, store, "GET / HTTP/1.1\r\nHost: report.test", "request", "HTTP 200", "response")
	path := filepath.Join(store.Dir, "blobs", snapshot.RespHash[:2], snapshot.RespHash+".bin")
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if appendix, err := renderDeliveryTrafficEvidence(store, []db.FindingTrafficBinding{{Snapshot: snapshot}}); err == nil || appendix != "" {
		t.Fatalf("damaged evidence was rendered: %q, %v", appendix, err)
	}
}

func TestDeliveryPacketFencePreservesMarkdownInHTTPBody(t *testing.T) {
	packet := "HTTP/1.1 200 OK\r\n\r\n```\n## 证据说明\n```"
	block := markdownPacketBlock(packet)
	if !strings.HasPrefix(block, "````http\n") || !strings.HasSuffix(block, "\n````") || !strings.Contains(block, packet) {
		t.Fatalf("HTTP body escaped its evidence code block: %s", block)
	}
}

func TestStripDeliveryTrafficEvidenceIgnoresMarkerInsideHTTPPacket(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	packet := "HTTP/1.1 200 OK\r\n\r\n" + deliveryEvidenceAppendixMarker + "\n## 响应正文中的标题\n```"
	report := deliveryReportFixture("测试结论", vector) + "\n\n### 本机留存报文\n\n" + markdownPacketBlock(packet)
	if got := stripDeliveryTrafficEvidence(report); got != report {
		t.Fatalf("marker inside the stored HTTP body truncated the report: %s", got)
	}
	withAppendix := report + "\n\n" + deliveryEvidenceAppendixMarker + "\n### 旧平台附录\n\n旧内容"
	if got := stripDeliveryTrafficEvidence(withAppendix); got != report {
		t.Fatalf("automatic appendix was not removed independently of packet markers: %s", got)
	}
	inlineMarker := "正文引用 " + deliveryEvidenceAppendixMarker + " 作为证据。"
	if got := stripDeliveryTrafficEvidence(inlineMarker); got != inlineMarker {
		t.Fatalf("inline marker truncated narrative: %s", got)
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
	ownerContent := deliveryReportFixture("owner report", vector)
	childContent := deliveryReportFixture("child report", vector)
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

	if code := put(ownerID, ownerContent, vector, 0); code != http.StatusOK {
		t.Fatalf("save owner report: status=%d", code)
	}
	if code := put(childID, childContent, vector, 0); code != http.StatusOK {
		t.Fatalf("save inherited report: status=%d", code)
	}
	ownerSaved := get(ownerID)
	if owner := ownerSaved; stripDeliveryTrafficEvidence(owner.Content) != ownerContent || !owner.Exists {
		t.Fatalf("owner report was not persisted independently: %+v", owner)
	}
	if inherited := get(childID); stripDeliveryTrafficEvidence(inherited.Content) != childContent || !inherited.Exists {
		t.Fatalf("inherited report was not persisted independently: %+v", inherited)
	}
	if w := request(http.MethodGet, fmt.Sprintf("/api/tasks/%d/findings/%d/delivery-report", outsiderID, finding.FindingID), ""); w.Code != http.StatusNotFound {
		t.Fatalf("unrelated task accessed finding report: status=%d body=%s", w.Code, w.Body.String())
	}

	if code := put(ownerID, ownerContent, "CVSS:4.0/AV:N", 0); code != http.StatusBadRequest {
		t.Fatalf("invalid vector save status=%d", code)
	}
	if got := get(ownerID); got.Content != ownerSaved.Content {
		t.Fatalf("invalid vector overwrote saved report: %+v", got)
	}
	if code := put(ownerID, strings.Replace(ownerContent, "## 攻击链路", "## 其他章节", 1), vector, 0); code != http.StatusBadRequest {
		t.Fatalf("invalid report structure save status=%d", code)
	}
	if got := get(ownerID); got.Content != ownerSaved.Content {
		t.Fatalf("invalid template overwrote saved report: %+v", got)
	}

	seedTraffic := func(id, path, requestHead, requestBody, responseBody string) {
		t.Helper()
		responseHead := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=response-cookie"
		_, err := s.m.traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,1,'delivery.local','POST',?,?,200,'application/json',?,?,'')`,
			id, path, "http://delivery.local"+path, len(requestBody), len(responseBody))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.m.traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body)
VALUES(?,?,?,?,?)`, id, requestHead, responseHead, []byte(requestBody), []byte(responseBody))
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
	for _, check := range []struct{ packet, want string }{
		{requestPacket, "POST /proof"},
		{requestPacket, "POST /baseline"},
		{responsePacket, "proof response"},
		{responsePacket, "baseline response"},
	} {
		if !strings.Contains(check.packet, check.want) {
			t.Fatalf("delivery packet omitted bound traffic %q: %s", check.want, check.packet)
		}
	}
	for _, secret := range []string{"query-secret", "header-secret", "request-cookie", "body-secret", "response-cookie", "response-secret"} {
		if !strings.Contains(requestPacket+responsePacket, secret) {
			t.Fatalf("delivery packet changed synthetic original evidence %q", secret)
		}
	}
	if code := put(ownerID, deliveryReportFixture("stale overwrite", vector), vector, 0); code != http.StatusConflict {
		t.Fatalf("stale report save status=%d", code)
	}
	stale := get(ownerID)
	if stale.Content != ownerSaved.Content || stale.EvidenceVersion != 0 || stale.CurrentEvidenceVersion != 1 {
		t.Fatalf("stale evidence changed saved report or version state: %+v", stale)
	}
	if code := put(ownerID, ownerContent, vector, traffic.Version); code != http.StatusOK {
		t.Fatalf("save current evidence: status=%d", code)
	}
	current := get(ownerID)
	if err := validateDeliveryReportTemplate(current.Content, vector); err != nil {
		t.Fatalf("saved evidence broke the report template: %v", err)
	}
	if strings.Count(current.Content, deliveryEvidenceAppendixMarker) != 1 || !strings.Contains(current.Content, "baseline response") || !strings.Contains(current.Content, "proof response") {
		t.Fatalf("saved report did not include all bound evidence once: %s", current.Content)
	}
	if code := put(ownerID, current.Content, vector, traffic.Version); code != http.StatusOK {
		t.Fatalf("resave generated evidence: status=%d", code)
	}
	if resaved := get(ownerID); resaved.Content != current.Content {
		t.Fatalf("resave duplicated or changed the automatic appendix: %s", resaved.Content)
	}
}

func deliveryReportFixture(description, vector string) string {
	return fmt.Sprintf(`# 测试系统-模块 /test 测试缺陷：测试结果

漏洞名称：测试系统-模块 /test 测试缺陷
CVSS 4.0：%s  评分 待计算（待计算）

## 描述

%s

### 定级依据

此为合成测试，影响未验证。

## 修复

配置和源码位置未验证。

## 测试过程

### 发现过程与攻击思路

工具、参数、判据和时间未记录。

### 失败尝试与未验证项

未取得失败尝试记录，实际影响未验证。

## 攻击链路

利用前提和影响未验证。

## 证据说明

来源为本地合成测试记录。

### Burp 复现

原始请求未采集，Burp 复测未验证。

### 复测标准

业务判据未验证。`, vector, description)
}

func deliveryPacketFixture(t *testing.T, store *evidence.Store, requestHead, requestBody, responseHead, responseBody string) db.TrafficEvidenceSnapshot {
	t.Helper()
	writeBody := func(body string) (string, int64) {
		raw := []byte(body)
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		path := filepath.Join(store.Dir, "blobs", hash[:2], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return hash, int64(len(raw))
	}
	requestHash, requestLen := writeBody(requestBody)
	responseHash, responseLen := writeBody(responseBody)
	return db.TrafficEvidenceSnapshot{ReqHead: requestHead, RespHead: responseHead, ReqHash: requestHash, ReqLen: requestLen, RespHash: responseHash, RespLen: responseLen}
}

type FindingDeliveryReport struct {
	Content                string `json:"content"`
	EvidenceVersion        int64  `json:"evidence_version"`
	CurrentEvidenceVersion int64  `json:"current_evidence_version"`
	Exists                 bool   `json:"exists"`
}
