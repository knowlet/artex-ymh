import { expect, test } from "@playwright/test";
import path from "node:path";

const E2E_PASSWORD = process.env.ARTEX_E2E_PASSWORD ?? "ui-e2e-disposable";
const UNIQUE = `ui-e2e-${Date.now()}`;

async function ensureAuthed(request: import("@playwright/test").APIRequestContext) {
  const status = await request.get("/api/auth/status");
  const body = await status.json();
  if (!body.initialized) {
    await request.post("/api/auth/init", { data: { password: E2E_PASSWORD } });
  }
  const login = await request.post("/api/auth/login", {
    data: { username: "ARTEX", password: E2E_PASSWORD },
  });
  expect(login.ok()).toBeTruthy();
  return (await login.json()).token as string;
}

test.describe("rendered UI workflows (real backend)", () => {
  test("login page rejects anonymous tasks; authorized list loads", async ({ page, request }) => {
    const deny = await request.get("/api/tasks");
    expect(deny.status()).toBe(401);

    await page.goto("/login");
    await expect(page.locator("body")).toBeVisible();

    const token = await ensureAuthed(request);
    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);
    await page.goto("/function/tasks");
    await expect(page).toHaveURL(/\/function\/tasks/);
    await expect(page.getByRole("button", { name: /新建任务/ })).toBeVisible();
  });

  test("create task via rendered sheet (CRUD create + list read)", async ({ page, request }) => {
    const token = await ensureAuthed(request);
    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);
    await page.goto("/function/tasks");
    await page.getByRole("button", { name: /新建任务/ }).click();
    await page.getByLabel("描述").fill(`desc ${UNIQUE}`);
    await page.getByLabel("目标").fill(`goal ${UNIQUE}`);
    await page.getByLabel(/名称/).fill(`name-${UNIQUE}`);
    await page.getByRole("button", { name: /^创建$/ }).click();
    await expect(page.getByText("任务已创建")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("main").getByText(`desc ${UNIQUE}`)).toBeVisible({ timeout: 15_000 });
  });

  test("staging chat upload via UI control", async ({ page, request }) => {
    const token = await ensureAuthed(request);
    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);
    await page.goto("/function/tasks");
    await page.getByRole("button", { name: /新建任务/ }).click();
    const fileInput = page.locator('input[type="file"]').first();
    const fixture = path.join(__dirname, "fixtures", "upload-sample.txt");
    await fileInput.setInputFiles(fixture);
    await expect(page.getByText("upload-sample.txt")).toBeVisible({ timeout: 10_000 });
  });

  test("settings update card renders for authorized user", async ({ page, request }) => {
    const token = await ensureAuthed(request);
    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);
    await page.goto("/system/settings");
    await expect(page.getByRole("button", { name: /检查更新/ })).toBeVisible();
  });
});
