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

const task = {
  id: "73",
  name: "交付报告验收任务",
  description: "交付报告页面回归",
  goal: "验证单漏洞交付报告行为",
  status: "done",
  created_at: new Date().toISOString(),
  created_unix: Math.floor(Date.now() / 1000),
  goals_total: 0,
  goals_met: 0,
  findings: { critical: 0, high: 1, medium: 1, low: 0 },
  in_flight: 0,
};

const findings = [
  { finding_id: "1001", task_id: "73", name: "权限校验缺失", vulnclass: "越权", severity: "high" },
  { finding_id: "1002", task_id: "73", name: "输入校验缺失", vulnclass: "注入", severity: "medium" },
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

test("delivery report generation, editing, copy, persistence, isolation, and stale evidence", async ({
  context,
  page,
  baseURL,
}) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await context.addCookies([{ name: "artex_token", value: "delivery-report-e2e", url: baseURL }]);
  await context.addInitScript(() => localStorage.setItem("artex_token", "delivery-report-e2e"));

  const saved = new Map<string, { content: string; cvss_vector: string; evidence_version: number }>();
  const currentEvidenceVersion = new Map<string, number>();
  currentEvidenceVersion.set("1001", 1);
  const generationState: { fail: boolean } = { fail: false };
  let generationCalls = 0;
  const generated = {
    cvss_vector: officialVectors[0].vector,
    description: "接口未校验当前用户是否拥有目标记录的访问权限。",
    remediation:
      "在读取记录前校验当前用户是否有权访问该记录，阻止未经授权的数据读取；根据现有证据，修复可限定在目标记录查询入口。",
    test_process: "通过 API 直接请求目标记录接口，确认未授权的记录编号仍被接受。",
    attack_chain: "POST /api/records/{id}\n└── 服务端未校验记录归属\n    └── 返回目标记录",
    discovery_path: "通过 API 直接请求漏洞记录接口并更换记录编号发现。",
    request_packet: "POST /api/records/42 HTTP/1.1\nHost: app.example\nAuthorization: Bearer report-token",
    response_packet: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":42}',
    evidence_version: 0,
  };

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();
    const json = (value: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });

    if (path === "/api/report") {
      await route.fulfill({
        status: 200,
        contentType: "text/markdown",
        body: "# 现有详细报告\n\n详细报告原文保持不变。",
      });
      return;
    }
    if (path === "/api/tasks") {
      await json({ tasks: [task], active: task.id });
      return;
    }
    if (path === "/api/tasks/73") {
      await json(task);
      return;
    }
    if (path === "/api/stats") {
      await json({});
      return;
    }
    if (path === "/api/llm/profiles") {
      await json({ profiles: [] });
      return;
    }
    if (path === "/api/intercept/task/73") {
      await json({ items: [] });
      return;
    }
    if (path === "/api/exploration/findings") {
      await json(findings);
      return;
    }
    const reportMatch = path.match(/^\/api\/tasks\/73\/findings\/(\d+)\/delivery-report$/);
    if (reportMatch && method === "GET") {
      const findingId = reportMatch[1];
      const record = saved.get(findingId);
      await json({
        task_id: "73",
        finding_id: findingId,
        content: record?.content ?? "",
        cvss_vector: record?.cvss_vector ?? "",
        evidence_version: record?.evidence_version ?? 0,
        current_evidence_version: currentEvidenceVersion.get(findingId) ?? 0,
        exists: Boolean(record),
      });
      return;
    }
    if (reportMatch && method === "PUT") {
      const findingId = reportMatch[1];
      const input = request.postDataJSON() as { content: string; cvss_vector: string; evidence_version: number };
      saved.set(findingId, input);
      await json({
        task_id: "73",
        finding_id: findingId,
        ...input,
        current_evidence_version: currentEvidenceVersion.get(findingId) ?? input.evidence_version,
        exists: true,
      });
      return;
    }
    const generateMatch = path.match(/^\/api\/tasks\/73\/findings\/(\d+)\/delivery-report\/generate$/);
    if (generateMatch && method === "POST") {
      generationCalls++;
      if (generationState.fail) {
        await json({ error: "模拟模型调用失败" }, 502);
        return;
      }
      await json({ ...generated, evidence_version: currentEvidenceVersion.get(generateMatch[1]) ?? 0 });
      return;
    }

    await json({});
  });

  await page.goto("/function/tasks/detail?id=73");
  await page.getByRole("tab", { name: "报告" }).click();
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();
  await expect(page.getByText("交付报告（单漏洞 Markdown）")).toBeVisible();

  const selector = page.getByLabel("选择漏洞");
  await expect(selector.locator("option")).toHaveCount(2);
  const editor = page.getByRole("textbox", { name: "Markdown 编辑" });
  const vectorInput = page.getByRole("textbox", { name: "CVSS 4.0 Base 向量" });
  const saveButton = page.getByRole("button", { name: "保存" });
  const generateButton = page.getByRole("button", { name: "生成草稿" });
  await expect(editor).toHaveValue("");
  await expect(page.getByText("漏洞证据已更新。请重新生成报告并复核后保存，避免交付内容引用旧证据。")).toHaveCount(0);
  await editor.fill("手工编写的交付报告。");
  await vectorInput.fill(officialVectors[0].vector);
  await expect(saveButton).toBeEnabled();
  await saveButton.click();
  await expect(page.getByText("交付报告已保存")).toBeVisible();
  expect(saved.get("1001")?.evidence_version).toBe(1);
  const manualSavedContent = saved.get("1001")?.content;

  await generateButton.click();
  await expect(editor).toHaveValue(/## 测试过程/);
  await expect(editor).toHaveValue(/### 发现路径说明/);
  await expect(editor).toHaveValue(/### Burp 复测请求/);
  await expect(editor).toHaveValue(/Authorization: Bearer report-token/);
  await expect(editor).toHaveValue(/## 修复建议[\s\S]*目标记录查询入口/);
  await expect(page.getByText("漏洞名称：权限校验缺失", { exact: true })).toBeVisible();
  expect(generationCalls).toBe(1);

  await vectorInput.fill("CVSS:4.0/AV:N");
  await expect(page.getByText("CVSS 4.0 Base 向量格式无效或不完整，无法计算评分。")).toBeVisible();
  await expect(saveButton).toBeDisabled();
  expect(saved.get("1001")?.content).toBe(manualSavedContent);

  await vectorInput.fill(officialVectors[2].vector);
  await expect(page.getByText("8.5 · 高危")).toBeVisible();
  await editor.fill(`${await editor.inputValue()}\n人工复核补充：只修复对象级授权判断。`);
  const expectedMarkdown = await editor.inputValue();
  await expect(page.getByText("人工复核补充：只修复对象级授权判断。", { exact: true })).toBeVisible();
  await saveButton.click();
  await expect(page.getByText("交付报告已保存")).toBeVisible();
  expect(saved.get("1001")?.cvss_vector).toBe(officialVectors[2].vector);

  await page.getByRole("button", { name: "复制" }).last().click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(expectedMarkdown);

  generationState.fail = true;
  await generateButton.click();
  await expect(page.getByText("模拟模型调用失败")).toBeVisible();
  await expect(editor).toHaveValue(expectedMarkdown);
  expect(saved.get("1001")?.content).toBe(expectedMarkdown);

  await selector.selectOption("1002");
  await expect(editor).toHaveValue("");
  expect(saved.has("1002")).toBe(false);
  await selector.selectOption("1001");
  await expect(editor).toHaveValue(expectedMarkdown);

  currentEvidenceVersion.set("1001", 2);
  await page.reload();
  await page.getByRole("tab", { name: "报告" }).click();
  await expect(page.getByText("漏洞证据已更新。请重新生成报告并复核后保存，避免交付内容引用旧证据。")).toBeVisible();
  await expect(page.getByRole("button", { name: "保存" })).toBeDisabled();
  await expect(page.getByRole("textbox", { name: "Markdown 编辑" })).toHaveValue(expectedMarkdown);
  await expect(page.getByText("详细报告原文保持不变。")).toBeVisible();
});
