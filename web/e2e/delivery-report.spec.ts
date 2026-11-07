import { expect, test } from "@playwright/test";

import { scoreCVSS4Base } from "../src/lib/cvss-v4";

const officialVectors = [
  {
    vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 7.3,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    score: 5.1,
    severity: "中危",
  },
  {
    vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 8.5,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 8.2,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 7.1,
    severity: "高危",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    score: 9.3,
    severity: "严重",
  },
  {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    score: 8.7,
    severity: "高危",
  },
];

test("CVSS-B score matches published FIRST CVSS v4.0 Base examples", () => {
  for (const example of officialVectors) {
    expect(scoreCVSS4Base(example.vector)).toMatchObject({ score: example.score, severity: example.severity });
  }
});

test("CVSS-B scoring follows FIRST's reference lookup for a conflicting example", () => {
  const vector = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
  expect(scoreCVSS4Base(vector)).toMatchObject({ score: 9.2, severity: "严重" });
});

test("finding detail shows its paired delivery report with AI CVSS and copy", async ({
  context,
  page,
  baseURL,
}) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await context.addCookies([{ name: "artex_token", value: "delivery-report-e2e", url: baseURL }]);
  await context.addInitScript(() => localStorage.setItem("artex_token", "delivery-report-e2e"));

  const reportText = [
    "# 漏洞名称：权限校验缺失",
    "",
    `- **CVSS 4.0 Base 向量（CVSS-B）**：${officialVectors[0].vector}`,
    "- **CVSS 4.0 评分**：1.0（CVSS-B）",
    "- **漏洞等级**：低危",
    "",
    "## 漏洞描述",
    "接口未校验当前用户是否拥有目标记录的访问权限。",
    "",
    "## 修复建议",
    "在读取记录前校验当前用户是否有权访问该记录。",
    "",
    "## 测试过程",
    "通过 API 直接请求目标记录接口，确认未授权的记录编号仍被接受。",
    "",
    "## 攻击链路",
    "POST /api/records/{id}\n└── 服务端未校验记录归属\n    └── 返回目标记录",
    "",
    "## Burp 复测请求",
    "```http\nPOST /api/records/42 HTTP/1.1\nHost: app.example\n```",
    "",
    "## 返回包",
    '```http\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":42}\n```',
  ].join("\n");
  let reportStale = false;

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();
    const json = (value: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });

    if (path === "/api/exploration/findings/1001" && method === "GET") {
      await json({
        id: "1001",
        finding_id: "1001",
        task_id: "73",
        name: "权限校验缺失",
        vulnclass: "越权",
        severity: "high",
        status: "confirmed",
        summary: "接口未校验当前用户是否拥有目标记录的访问权限。",
        evidence: "使用低权限账号读取其他用户的记录。",
        report: "# 详细报告\n\n详细报告原文保持不变。",
        report_stale: false,
        delivery_report: reportText,
        delivery_report_cvss_vector: officialVectors[0].vector,
        delivery_report_stale: reportStale,
        ts: new Date().toISOString(),
      });
      return;
    }
    if (path === "/api/exploration/findings/1001/traffic" && method === "GET") {
      await json({ finding_id: "1001", version: 1, report_version: 0, bindings: [] });
      return;
    }
    if (path === "/api/exploration/findings/1001/retests" && method === "GET") {
      await json({ retests: [] });
      return;
    }

    await json({});
  });

  await page.goto("/function/findings/detail?id=1001");
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();
  await expect(page.getByText("交付报告", { exact: true })).toBeVisible();
  await expect(page.getByText(/CVSS 4\.0 评分.*7\.3（CVSS-B）/)).toBeVisible();
  await expect(page.getByText(/漏洞等级.*高危/)).toBeVisible();
  await expect(page.getByText(officialVectors[0].vector)).toBeVisible();
  await expect(page.getByText("选择漏洞", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "生成草稿" })).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: "Markdown 编辑" })).toHaveCount(0);

  await page.getByRole("button", { name: "复制交付报告" }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain(`- **CVSS 4.0 Base 向量（CVSS-B）**：${officialVectors[0].vector}`);
  expect(copied).toContain("- **CVSS 4.0 评分**：7.3（CVSS-B）");
  expect(copied).toContain("- **漏洞等级**：高危");

  reportStale = true;
  await page.reload();
  await expect(page.getByText("漏洞证据已变化，交付报告可能引用旧证据。")).toBeVisible();
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();
});
