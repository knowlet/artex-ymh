import { expect, test } from "@playwright/test";

// Real browser checks against disposable local server — no LLM calls.
test.describe("upgrade smoke", () => {
  test("login page renders", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  });

  test("setup route reachable when unconfigured", async ({ page }) => {
    const res = await page.goto("/setup");
    expect(res?.status()).toBeLessThan(500);
    await expect(page.locator("body")).toBeVisible();
  });
});
