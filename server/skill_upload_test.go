package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestValidSkillName(t *testing.T) {
	ok := []string{"web-recon", "a", "nuclei2", "中文技能", "端口扫描-x", "日本語スキル"}
	bad := []string{
		"", "Web-Recon", "-lead", "trail-", "dou--ble", "has space", "中文 技能",
		"dot.name", "a/b", `a\b`, "..", ".", "中文/技能", "sk\x00ill", "中‮文",
		strings.Repeat("a", 65), "1abc", "中文技能!",
	}
	for _, n := range ok {
		if !validSkillName(n) {
			t.Errorf("validSkillName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validSkillName(n) {
			t.Errorf("validSkillName(%q) = true, want false", n)
		}
	}
}

func TestSkillRelPath(t *testing.T) {
	ok := map[string]string{
		"SKILL.md":           "SKILL.md",
		"scripts/run.py":     "scripts/run.py",
		"参考/中文说明.md":         "参考/中文说明.md",
		"references/a b.txt": "references/a b.txt",
		"./SKILL.md":         "SKILL.md",
		"assets/图片-1_v2.png": "assets/图片-1_v2.png",
	}
	for in, want := range ok {
		got, msg := skillRelPath(in)
		if msg != "" || got != want {
			t.Errorf("skillRelPath(%q) = (%q, %q), want (%q, \"\")", in, got, msg, want)
		}
	}
	bad := []string{
		"", "../etc/passwd", "a/../../b", "/abs/path", "a//b", `..\..\x`,
		"%2e%2e/x", "a\x00b", "中文 名.md", "中‮文.md", "a#b.md", "a?b.md",
		"a:b.md", string([]byte{0xd6, 0xd0}) + ".md", // 裸 GBK 字节：非法 UTF-8
		strings.Repeat("a", maxSkillPathLen+1),
	}
	for _, in := range bad {
		if got, msg := skillRelPath(in); msg == "" {
			t.Errorf("skillRelPath(%q) = (%q, \"\"), want rejection", in, got)
		}
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// zipFile describes one entry for buildZip.
type zipFile struct {
	name    string
	body    string
	method  uint16
	nonUTF8 bool // write the name bytes as-is (GBK 包)
}

func buildZip(t *testing.T, files ...zipFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.RegisterCompressor(zipMethodZstd, zstd.ZipCompressor())
	// Deflate64 没有纯 Go 编码器；这里原样写入，只是为了给条目打上 method 9 的标记 ——
	// 断言的是「方法不支持时给什么提示」，不会真去解压它。
	zw.RegisterCompressor(zipMethodDeflate64, func(w io.Writer) (io.WriteCloser, error) {
		return nopWriteCloser{w}, nil
	})
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: f.method, NonUTF8: f.nonUTF8}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", f.name, err)
		}
		if _, err := io.WriteString(w, f.body); err != nil {
			t.Fatalf("write %q: %v", f.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// uploadZip posts raw zip bytes without a database; rejection paths remain testable
// without starting the PostgreSQL-backed manager.
func uploadZip(t *testing.T, skillDir string, filename string, data []byte) (*httptest.ResponseRecorder, map[string]any) {
	return uploadZipToServer(t, &Server{skillDir: skillDir}, filename, data)
}

func uploadZipWithManager(t *testing.T, skillDir string, skillName string, filename string, data []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping successful upload test", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})
	// A unique name keeps this cleanup from touching existing user authorization.
	t.Cleanup(func() {
		if err := m.pg.DeleteSkillVisibility(skillName); err != nil {
			t.Errorf("remove test skill visibility: %v", err)
		}
	})
	return uploadZipToServer(t, &Server{m: m, skillDir: skillDir}, filename, data)
}

func uploadZipToServer(t *testing.T, s *Server, filename string, data []byte) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/skills/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	s.fsUploadSkill(rr, req)

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func zhSkillMD(skillName string) string {
	return "---\nname: " + skillName + "\ndescription: 测试\n---\n正文\n"
}

// A zstd-compressed archive (WinZip 的可选压缩方式) used to blow up with
// "zip: unsupported compression"; it now installs like any Deflate archive.
func TestUploadSkillZstdAndChineseNames(t *testing.T) {
	dir := t.TempDir()
	skillName := "中文技能-" + uuid.NewString()
	data := buildZip(t,
		zipFile{name: skillName + "/SKILL.md", body: zhSkillMD(skillName), method: zipMethodZstd},
		zipFile{name: skillName + "/参考/说明 文档.md", body: "参考", method: zipMethodZstd},
		zipFile{name: skillName + "/scripts/run.py", body: "print(1)", method: zip.Deflate},
	)
	rr, out := uploadZipWithManager(t, dir, skillName, skillName+".zip", data)
	if rr.Code != 201 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body)
	}
	if out["name"] != skillName {
		t.Fatalf("name = %v, want %s", out["name"], skillName)
	}
	for _, rel := range []string{"SKILL.md", "参考/说明 文档.md", "scripts/run.py"} {
		if _, err := os.Stat(filepath.Join(dir, skillName, rel)); err != nil {
			t.Errorf("missing extracted file %q: %v", rel, err)
		}
	}
}

// GBK-named entries (7-Zip / 资源管理器 on Chinese Windows) must be decoded rather
// than rejected as invalid UTF-8 paths.
func TestUploadSkillGBKNames(t *testing.T) {
	gbk := func(s string) string {
		b, err := simplifiedchinese.GBK.NewEncoder().String(s)
		if err != nil {
			t.Fatalf("gbk encode %q: %v", s, err)
		}
		return b
	}
	dir := t.TempDir()
	skillName := "中文技能-" + uuid.NewString()
	data := buildZip(t,
		zipFile{name: gbk(skillName + "/SKILL.md"), body: zhSkillMD(skillName), method: zip.Deflate, nonUTF8: true},
		zipFile{name: gbk(skillName + "/参考资料.md"), body: "内容", method: zip.Deflate, nonUTF8: true},
	)
	rr, out := uploadZipWithManager(t, dir, skillName, "skill.zip", data)
	if rr.Code != 201 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body)
	}
	if out["name"] != skillName {
		t.Fatalf("name = %v, want %s", out["name"], skillName)
	}
	if _, err := os.Stat(filepath.Join(dir, skillName, "参考资料.md")); err != nil {
		t.Errorf("GBK-named entry not extracted: %v", err)
	}
}

func TestUploadSkillWithoutManagerReturnsServiceUnavailable(t *testing.T) {
	dir := t.TempDir()
	data := buildZip(t,
		zipFile{name: "demo/SKILL.md", body: "---\nname: demo\n---\n", method: zip.Deflate},
	)
	rr, out := uploadZip(t, dir, "demo.zip", data)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (body %s)", rr.Code, http.StatusServiceUnavailable, rr.Body)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "默认授权未完成") {
		t.Fatalf("error = %q, want database-unavailable message", msg)
	}
	if _, err := os.Stat(filepath.Join(dir, "demo", "SKILL.md")); err != nil {
		t.Fatalf("skill file should remain installed after database failure: %v", err)
	}
}

// An archive we genuinely cannot decode should name the method in Chinese instead of
// surfacing "zip: unsupported compression algorithm".
func TestUploadSkillUnsupportedMethod(t *testing.T) {
	data := buildZip(t,
		zipFile{name: "demo/SKILL.md", body: "---\nname: demo\n---\n", method: zipMethodDeflate64},
	)
	rr, out := uploadZip(t, t.TempDir(), "demo.zip", data)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "Deflate64") || !strings.Contains(msg, "不支持的压缩方式") {
		t.Fatalf("error = %q, want a Chinese message naming Deflate64", msg)
	}
}

func TestUploadSkillEncrypted(t *testing.T) {
	data := buildZip(t, zipFile{name: "demo/SKILL.md", body: "---\nname: demo\n---\n", method: zip.Deflate})
	// flip the "encrypted" general-purpose flag bit in the local file header
	// (offset 6) and in the central directory copy (offset 8).
	local := bytes.Index(data, []byte("PK\x03\x04"))
	central := bytes.Index(data, []byte("PK\x01\x02"))
	if local < 0 || central < 0 {
		t.Fatal("could not locate zip headers")
	}
	data[local+6] |= 1
	data[central+8] |= 1

	rr, out := uploadZip(t, t.TempDir(), "demo.zip", data)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "已加密") {
		t.Fatalf("error = %q, want 加密 hint", msg)
	}
}

// Zip-slip must still be refused now that the path check accepts Unicode.
func TestUploadSkillRejectsTraversal(t *testing.T) {
	data := buildZip(t,
		zipFile{name: "demo/SKILL.md", body: "---\nname: demo\n---\n", method: zip.Deflate},
		zipFile{name: "demo/../../evil.sh", body: "rm -rf /", method: zip.Deflate},
	)
	dir := t.TempDir()
	rr, out := uploadZip(t, dir, "demo.zip", data)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "非法路径") {
		t.Fatalf("error = %q, want 非法路径", msg)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("upload left files behind: %v", entries)
	}
}

func TestSkillNameFromFrontmatterQuoted(t *testing.T) {
	got := skillNameFromFrontmatter([]byte("---\nname: \"中文技能\"\ndescription: x\n---\n"))
	if got != "中文技能" {
		t.Fatalf("name = %q, want 中文技能", got)
	}
}
