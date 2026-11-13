import { expect, test } from "@playwright/test";

import { randomUUID } from "node:crypto";

const mcpSecretRef = (name: string) => `\${ARTEX_MCP_SECRET_${name}}`;

test("ZAP preset stays disabled and unassigned", async ({ context, page, baseURL }) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  const savedConfigs: Record<string, unknown>[] = [];
  const writeRequests: string[] = [];

  await context.addCookies([{ name: "artex_token", value: token, url: baseURL }]);
  await context.addInitScript((value) => {
    localStorage.setItem("artex_token", value);
  }, token);

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const { pathname } = new URL(request.url());
    let response: Record<string, unknown> = {};

    if (request.method() !== "GET") writeRequests.push(`${request.method()} ${pathname}`);
    if (pathname === "/api/agents") {
      response = { agents: [] };
    } else if (pathname === "/api/mcp" && request.method() === "GET") {
      response = { servers: [] };
    } else if (pathname === "/api/mcp" && request.method() === "POST") {
      savedConfigs.push(request.postDataJSON() as Record<string, unknown>);
      response = { id: savedConfigs.length };
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(response),
    });
  });

  await page.goto("/system/mcp");

  await page.getByRole("button", { name: "OWASP ZAP 预设" }).click();
  await expect(page.getByLabel("名称")).toHaveValue("OWASP ZAP");
  await expect(page.getByLabel("远程 URL")).toHaveValue("http://127.0.0.1:8282");
  await expect(page.getByLabel(/请求头/)).toHaveValue(`Authorization=${mcpSecretRef("ZAP_KEY")}`);
  await page.getByRole("button", { name: "添加", exact: true }).click();

  expect(savedConfigs).toHaveLength(1);
  expect(savedConfigs[0]).toMatchObject({
    name: "OWASP ZAP",
    transport: "http",
    enabled: false,
    url: "http://127.0.0.1:8282",
    env: { Authorization: mcpSecretRef("ZAP_KEY") },
  });
  expect(writeRequests).toEqual(["POST /api/mcp"]);
});
