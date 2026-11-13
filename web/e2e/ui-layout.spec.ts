import { expect, test } from "@playwright/test";

import { randomUUID } from "node:crypto";

const longSkillName = `regression-skill-${"long-name-".repeat(16)}`;
const task = {
  id: "73",
  name: "CI layout task",
  description: "Task action layout regression",
  goal: "Check fixed operation column layout",
  status: "running",
  created_at: new Date().toISOString(),
  created_unix: Math.floor(Date.now() / 1000),
  goals_total: 0,
  goals_met: 0,
  findings: { critical: 0, high: 0, medium: 0, low: 0 },
  in_flight: 0,
};

test.beforeEach(async ({ context, page, baseURL }) => {
  if (!baseURL) throw new Error("Playwright baseURL is required");
  const token = randomUUID();
  await context.addCookies([{ name: "artex_token", value: token, url: baseURL }]);
  await context.addInitScript((value) => {
    localStorage.setItem("artex_token", value);
  }, token);

  await page.route("**/api/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    let response: Record<string, unknown> = {};

    if (pathname === "/api/skills") {
      response = {
        skills: [
          {
            name: longSkillName,
            description: "Layout regression fixture",
            files: [],
            calls: 0,
            tasks: 0,
            usage_agents: [],
            mcps: [],
          },
        ],
      };
    } else if (pathname === "/api/skills/missing") {
      response = { missing: [] };
    } else if (pathname === "/api/tasks") {
      response = { tasks: [task], active: task.id };
    } else if (pathname === "/api/task-categories") {
      response = { categories: [] };
    } else if (pathname === "/api/agents") {
      response = { agents: [] };
    } else if (pathname === "/api/mcp/servers") {
      response = { servers: [] };
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(response),
    });
  });
});

test("long unused Skill names wrap inside the overview column", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/system/skills");

  const skillTag = page.getByRole("button", { name: longSkillName, exact: true }).last();
  await expect(skillTag).toBeVisible();

  const bounds = await skillTag.boundingBox();
  if (!bounds) throw new Error("Skill tag has no bounding box");
  expect(bounds.height).toBeGreaterThan(24);

  const textLayout = await skillTag
    .locator("span")
    .last()
    .evaluate((element) => ({
      overflowWrap: getComputedStyle(element).overflowWrap,
      scrollWidth: element.scrollWidth,
      clientWidth: element.clientWidth,
    }));
  expect(textLayout.overflowWrap).toBe("anywhere");
  expect(textLayout.scrollWidth).toBeLessThanOrEqual(textLayout.clientWidth + 1);
  expect(pageErrors).toEqual([]);
});

test("task operation controls remain within the sticky action column", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.setViewportSize({ width: 734, height: 900 });
  await page.goto("/function/tasks");

  const row = page.getByRole("row", { name: /CI layout task/ });
  await expect(row).toBeVisible();
  const actionCell = row.getByRole("cell").last();
  const actionLinks = actionCell.locator("a, button");
  const tableContainer = row.locator('xpath=ancestor::div[@data-slot="table-container"]');
  await expect(tableContainer).toBeVisible();
  await expect(actionLinks).toHaveCount(5);
  await expect(actionCell.getByRole("button", { name: "暂停任务" })).toBeVisible();

  const beforeScroll = await actionCell.boundingBox();
  if (!beforeScroll) throw new Error("Task action cell has no bounding box before scrolling");

  const scroll = await tableContainer.evaluate((element) => {
    const container = element as HTMLElement;
    const before = container.scrollLeft;
    container.scrollLeft = container.scrollWidth;
    return {
      before,
      after: container.scrollLeft,
      scrollWidth: container.scrollWidth,
      clientWidth: container.clientWidth,
    };
  });
  expect(scroll.scrollWidth).toBeGreaterThan(scroll.clientWidth);
  expect(scroll.after).toBeGreaterThan(scroll.before);

  await actionCell.hover();
  const hoverBackgroundAlpha = await actionCell.evaluate((cell) => {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas 2D context is unavailable");
    context.fillStyle = getComputedStyle(cell).backgroundColor;
    context.fillRect(0, 0, 1, 1);
    return context.getImageData(0, 0, 1, 1).data[3];
  });
  expect(hoverBackgroundAlpha).toBe(255);

  const afterScroll = await actionCell.boundingBox();
  if (!afterScroll) throw new Error("Task action cell has no bounding box after scrolling");
  expect(Math.abs(afterScroll.x + afterScroll.width - (beforeScroll.x + beforeScroll.width))).toBeLessThanOrEqual(1);

  const layout = await actionCell.evaluate((cell) => {
    const cellBounds = cell.getBoundingClientRect();
    const actions = Array.from(cell.querySelectorAll("a, button"), (action) => {
      const bounds = action.getBoundingClientRect();
      return { left: bounds.left, right: bounds.right };
    });
    return { cellLeft: cellBounds.left, cellRight: cellBounds.right, viewportWidth: innerWidth, actions };
  });

  for (const action of layout.actions) {
    expect(action.left).toBeGreaterThanOrEqual(layout.cellLeft - 1);
    expect(action.right).toBeLessThanOrEqual(layout.cellRight + 1);
    expect(action.left).toBeGreaterThanOrEqual(0);
    expect(action.right).toBeLessThanOrEqual(layout.viewportWidth + 1);
  }
  expect(pageErrors).toEqual([]);
});
