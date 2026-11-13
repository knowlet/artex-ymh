import { test, expect } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";

function loadEnvFile(): { baseURL: string; token: string; pendingID: string; cancelPendingID: string } {
  const envFile = process.env.ADVISORY_E2E_ENV_FILE ?? path.join("/tmp", "artex-advisory-e2e.env");
  const raw = fs.readFileSync(envFile, "utf8");
  const vars: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) {
      const key = line.slice(0, i);
      vars[key] = line.slice(i + 1);
    }
  }
  return {
    baseURL: vars.ADVISORY_E2E_BASE_URL ?? "http://127.0.0.1:9877",
    token: vars.ADVISORY_E2E_TOKEN ?? "",
    pendingID: vars.ADVISORY_E2E_PENDING_ID ?? "0",
    cancelPendingID: vars.ADVISORY_E2E_CANCEL_PENDING_ID ?? "0",
  };
}

async function seedSession(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  token: string,
) {
  const base = process.env.ADVISORY_E2E_WEB_URL ?? "http://127.0.0.1:3000";
  await context.addCookies([{ name: "artex_session", value: "1", url: base }]);
  await context.addInitScript((tok) => {
    window.localStorage.setItem("artex_token", tok);
    document.cookie = "artex_session=1; path=/; SameSite=Lax";
  }, token);
  await page.goto("/system/intercept/approvals", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/system\/intercept\/approvals/, { timeout: 15_000 });
}

async function openPendingRow(page: import("@playwright/test").Page, pendingID: string) {
  await expect(page.getByRole("heading", { name: "审批记录" })).toBeVisible({ timeout: 30_000 });
  const pendingTable = page.getByRole("table", { name: "待处理审批" });
  await expect(pendingTable).toBeVisible({ timeout: 30_000 });
  await pendingTable.locator("tbody tr").filter({ hasText: pendingID }).first().click();
}

test.describe.configure({ mode: "serial" });

test.describe("approval advisory auto (fake provider, disposable PG)", () => {
  test("cancel while inference blocked: stop auto retry, discard finished model output", async ({ page, context }) => {
    const { token, cancelPendingID, baseURL } = loadEnvFile();
    test.skip(!token || cancelPendingID === "0", "ADVISORY_E2E env missing");

    const auth = { Authorization: `Bearer ${token}` };
    await expect
      .poll(
        async () => {
          const r = await page.request.get(`${baseURL}/api/e2e/advisory/inference-entered`);
          return r.status();
        },
        { timeout: 60_000 },
      )
      .toBe(200);

    const before = await (await page.request.get(`${baseURL}/api/intercept/pending/${cancelPendingID}/advisory`, { headers: auth })).json();
    expect(before.auto_cancelled).toBeFalsy();

    const cancelRes = await page.request.post(`${baseURL}/api/intercept/pending/${cancelPendingID}/advisory/cancel`, {
      headers: auth,
      data: "{}",
    });
    expect(cancelRes.ok()).toBeTruthy();

    const releaseRes = await page.request.post(`${baseURL}/api/e2e/advisory/release-inference`);
    expect(releaseRes.ok()).toBeTruthy();

    await expect
      .poll(async () => {
        const body = await (await page.request.get(`${baseURL}/api/intercept/pending/${cancelPendingID}/advisory`, { headers: auth })).json();
        return body.auto_cancelled === true && body.current !== true;
      })
      .toBeTruthy();

    const after = await (await page.request.get(`${baseURL}/api/intercept/pending/${cancelPendingID}/advisory`, { headers: auth })).json();
    expect(after.approval_status).toBe("pending");
    const state = after.assessment?.state;
    expect(state === undefined || state === "failed" || state === "stale" || !after.current).toBeTruthy();

    await seedSession(page, context, token);
    await openPendingRow(page, cancelPendingID);
    const advisory = page.getByLabel("智慧審查建議");
    await advisory.scrollIntoViewIfNeeded();
    await expect(advisory.getByText(/已停止自動重試/)).toBeVisible();
    await expect(advisory.getByText(/不會中斷進行中的模型請求/)).toBeVisible();
    await expect(advisory.getByRole("button", { name: /手動審查|手動重新審查/ })).toBeVisible();
  });

  test("queued → running → succeeded without manual review click", async ({ page, context }) => {
    const { token, baseURL } = loadEnvFile();
    test.skip(!token, "ADVISORY_E2E env missing");

    const auth = { Authorization: `Bearer ${token}` };
    const seedRes = await page.request.post(`${baseURL}/api/e2e/advisory/seed-auto-pending`);
    expect(seedRes.ok()).toBeTruthy();
    const { pending_id: pendingID } = (await seedRes.json()) as { pending_id: number };

    await seedSession(page, context, token);
    await openPendingRow(page, String(pendingID));

    const advisory = page.getByLabel("智慧審查建議");
    await advisory.scrollIntoViewIfNeeded();
    await expect(advisory).toBeVisible();
    await expect(advisory.getByText(/背景自動審查已啟用/)).toBeVisible();
    await expect(advisory.getByText(/已加入背景審查佇列|正在分析|風險：/)).toBeVisible({ timeout: 60_000 });
    await expect(advisory.getByText(/風險：/)).toBeVisible({ timeout: 90_000 });
    await expect(advisory.getByText(/並非授權/)).toBeVisible();

    const res = await page.request.get(`${baseURL}/api/intercept/pending/${pendingID}`, { headers: auth });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe("pending");
  });
});
