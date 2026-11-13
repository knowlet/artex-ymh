import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

const tokenPath = join(__dirname, ".runtime/access-token.txt");

function readAccessToken(): string {
  return readFileSync(tokenPath, "utf8").trim();
}

test.describe("findings detail — reproduction panel", () => {
  test.beforeEach(async ({ context }) => {
    const token = readAccessToken();
    await context.addInitScript((t) => {
      window.localStorage.setItem("artex_token", t);
    }, token);
  });

  test("finding with reproduction shows steps, request/response, and traffic link", async ({ page }) => {
    await page.goto("/function/findings/detail?id=9001");

    await expect(page.getByRole("heading", { name: /E2E With Reproduction/ })).toBeVisible();
    await expect(page.getByText("结构化复现过程")).toBeVisible();
    await expect(page.getByText("步骤 1")).toBeVisible();
    await expect(page.getByText("预期：200")).toBeVisible();
    await expect(page.getByText("证明：漏洞可复现")).toBeVisible();
    await expect(page.locator("pre", { hasText: "GET /e2e/vuln HTTP/1.1" })).toBeVisible();
    await expect(page.locator("pre", { hasText: "HTTP/1.1 200 OK" })).toBeVisible();

    const trafficLink = page.getByRole("link", { name: /查看流量包 e2e-ex-001/ });
    await expect(trafficLink).toHaveAttribute("href", /\/function\/traffic\/\?id=e2e-ex-001/);

    await trafficLink.click();
    await expect(page).toHaveURL(/\/function\/traffic\/?\?id=e2e-ex-001/);
    await expect(page.getByRole("cell", { name: "e2e.local", exact: true })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByText("http://e2e.local/e2e/vuln")).toBeVisible();
  });

  test("finding without reproduction hides the reproduction panel", async ({ page }) => {
    await page.goto("/function/findings/detail?id=9002");

    await expect(page.getByRole("heading", { name: /E2E Without Reproduction/ })).toBeVisible();
    await expect(page.getByText("结构化复现过程")).toHaveCount(0);
  });
});
