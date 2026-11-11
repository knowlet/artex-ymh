import { expect, test } from "@playwright/test";

const E2E_PASSWORD = process.env.ARTEX_E2E_PASSWORD ?? "upgrade-e2e-disposable";

test.describe("core workflows (real backend)", () => {
  test.beforeEach(async ({ request }) => {
    const status = await request.get("/api/auth/status");
    expect(status.ok()).toBeTruthy();
    const body = await status.json();
    if (!body.initialized) {
      const init = await request.post("/api/auth/init", {
        data: { password: E2E_PASSWORD },
      });
      expect(init.ok()).toBeTruthy();
    }
  });

  test("authorized API: login and list tasks", async ({ page, request }) => {
    const login = await request.post("/api/auth/login", {
      data: { username: "ARTEX", password: E2E_PASSWORD },
    });
    expect(login.ok()).toBeTruthy();
    const { token } = await login.json();
    expect(token).toBeTruthy();

    const tasks = await request.get("/api/tasks", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(tasks.ok()).toBeTruthy();

    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);
    await page.goto("/");
    await expect(page.locator("body")).toBeVisible();
  });

  test("rejected API without token", async ({ request }) => {
    const tasks = await request.get("/api/tasks");
    expect(tasks.status()).toBe(401);
  });

  test("health and setup UI", async ({ page, request }) => {
    const health = await request.get("/api/health");
    expect(health.ok()).toBeTruthy();
    const res = await page.goto("/login");
    expect(res?.status()).toBeLessThan(500);
    await expect(page.locator("body")).toBeVisible();
  });
});
