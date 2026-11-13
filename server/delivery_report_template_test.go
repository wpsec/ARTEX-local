package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/wpsec/ARTEX-local/agent"
)

func TestValidateDeliveryReportTemplate(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	valid := deliveryReportFixture("重复请求的实际影响未验证。", vector)
	cases := []struct {
		name   string
		report string
		valid  bool
	}{
		{"fixed template", valid, true},
		{"CRLF", strings.ReplaceAll(valid, "\n", "\r\n"), true},
		{"packet contains headings", valid + "\n\n" + markdownPacketBlock("HTTP/1.1 200 OK\n\n## 描述\n### Burp 复现"), true},
		{"tree contains headings", strings.Replace(valid, "利用前提和影响未验证。", "```text\n账号 A\n└ 请求及影响未验证\n## 修复\n```", 1), true},
		{"no title", strings.Replace(valid, "# 测试系统-模块 /test 测试缺陷：测试结果", "测试报告", 1), false},
		{"no finding name", strings.Replace(valid, "漏洞名称：测试系统-模块 /test 测试缺陷", "", 1), false},
		{"invalid header vector", strings.Replace(valid, vector, "CVSS:4.0/AV:N", 1), false},
		{"missing attack chain", strings.Replace(valid, "## 攻击链路", "### 攻击链路", 1), false},
		{"packet cannot supply attack chain", strings.Replace(valid, "## 攻击链路", "```http\n## 攻击链路\n```", 1), false},
		{"comment cannot supply attack chain", strings.Replace(valid, "## 攻击链路", "<!--\n## 攻击链路\n-->", 1), false},
		{"wrong section order", strings.Replace(valid, "## 修复", "## 测试过程", 1), false},
		{"duplicate section", valid + "\n\n## 描述\n重复章节。", false},
		{"empty remediation", strings.Replace(valid, "配置和源码位置未验证。", " \t\n", 1), false},
		{"missing failure subsection", strings.Replace(valid, "### 失败尝试与未验证项", "### 其他记录", 1), false},
		{"packet cannot supply Burp subsection", strings.Replace(valid, "### Burp 复现", "~~~http\n### Burp 复现\n~~~", 1), false},
		{"indented code cannot supply subsection", strings.Replace(valid, "### Burp 复现", "\t### Burp 复现", 1), false},
		{"empty retest subsection", strings.Replace(valid, "业务判据未验证。", "", 1), false},
		{"comment-only subsection", strings.Replace(valid, "业务判据未验证。", "<!-- TODO -->", 1), false},
		{"inline XSS payload", strings.Replace(valid, "重复请求的实际影响未验证。", "测试参数包含 `<!--`，实际影响未验证。", 1), true},
		{"multiple-backtick payload", strings.Replace(valid, "重复请求的实际影响未验证。", "测试参数包含 ``x`<!--``，实际影响未验证。", 1), true},
		{"fence info contains comment syntax", strings.Replace(valid, "重复请求的实际影响未验证。", "```text <!--\n实际影响未验证。\n```", 1), true},
		{"inline triple backticks", strings.Replace(valid, "重复请求的实际影响未验证。", "```payload```", 1), true},
		{"different valid header vector", strings.Replace(valid, "/PR:N/", "/PR:L/", 1), false},
		{"unclosed packet", valid + "\n\n```http\nGET / HTTP/1.1", false},
		{"unclosed comment", valid + "\n\n<!-- note", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDeliveryReportTemplate(tc.report, vector)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestFindingReportToolRejectsInvalidTemplateBeforeDatabase(t *testing.T) {
	old := agent.FindingTrafficBindingEnabled
	agent.FindingTrafficBindingEnabled = nil
	t.Cleanup(func() { agent.FindingTrafficBindingEnabled = old })
	input, err := json.Marshal(map[string]any{
		"finding_id": 1, "report": "详细报告", "delivery_report": "缺少攻击链的报告",
		"cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "evidence_version": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&Server{}).toolUpdateFindingReport().Call(context.Background(), input, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "固定模板") {
		t.Fatalf("invalid report was not rejected before database access: result=%v error=%v", result, err)
	}
}

func TestReporterTemplateUpgradeRecognizesDefaultsAndPreservesEdits(t *testing.T) {
	previous, err := os.ReadFile("testdata/reporter-default-v3.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reporterPromptNeedsTemplateUpgrade(string(previous)) {
		t.Fatal("previous stock default would not receive the fixed template")
	}
	attackChainOnly := strings.Replace(string(previous), "- 请求与响应证据：", "- 攻击链路：交付报告必须单独使用 Markdown 二级标题“攻击链路”，说明从利用前提到已证实影响的实际过程，按发生顺序写出每一步的请求或操作、系统响应及对应证据。只连接证据支持的步骤；未验证或缺失的环节明确标出，不用箭头缩写，也不把推测写成事实。\n- 请求与响应证据：", 1)
	if !reporterPromptNeedsTemplateUpgrade(attackChainOnly) {
		t.Fatal("attack-chain-only stock default would not receive the fixed template")
	}
	for _, customized := range []string{string(previous) + "\n用户自定义要求。", "自定义报告模板", agent.ReporterDefaultPrompt} {
		if reporterPromptNeedsTemplateUpgrade(customized) {
			t.Fatal("custom or already current prompt would be replaced")
		}
	}
}
