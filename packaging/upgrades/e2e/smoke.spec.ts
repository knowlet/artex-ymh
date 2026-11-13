import { expect, test } from "@playwright/test";

// Real browser checks against disposable local server — no LLM calls.
test.describe("upgrade smoke", () => {
  test("login route and API health", async ({ page, request }) => {
    const health = await request.get("/api/health");
    expect(health.ok()).toBeTruthy();
    const res = await page.goto("/login");
    expect(res?.status()).toBeLessThan(500);
    await expect(page.locator("body")).toBeVisible();
  });

  test("unauthenticated tasks API rejected", async ({ request }) => {
    const tasks = await request.get("/api/tasks");
    expect(tasks.status()).toBe(401);
  });
});
