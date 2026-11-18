import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const E2E_PASSWORD = process.env.ARTEX_E2E_PASSWORD ?? "ui-e2e-disposable";
const SEED_PATH = process.env.ARTEX_FINDINGS_SEED_PATH ?? "";
const FIXTURE = path.join(__dirname, "fixtures", "upload-sample.txt");

type Seed = {
  task_id: string;
  finding_id: number;
  summary_marker: string;
  report_marker: string;
  task_desc: string;
  upload_fixture_sha256?: string;
};

function loadSeed(): Seed {
  if (!SEED_PATH || !fs.existsSync(SEED_PATH)) {
    throw new Error(`missing seed JSON at ${SEED_PATH}`);
  }
  return JSON.parse(fs.readFileSync(SEED_PATH, "utf8")) as Seed;
}

async function login(request: import("@playwright/test").APIRequestContext) {
  const login = await request.post("/api/auth/login", {
    data: { username: "ARTEX", password: E2E_PASSWORD },
  });
  expect(login.ok()).toBeTruthy();
  return (await login.json()).token as string;
}

test.describe("findings export, report, upload bytes (real PG17 backend)", () => {
  const seed = loadSeed();

  test("export JSON contains seeded finding id and summary bytes", async ({ request }) => {
    const token = await login(request);
    const url = `/api/exploration/findings/export?format=json&scope=selected&ids=${seed.finding_id}`;
    const deny = await request.get(url);
    expect(deny.status()).toBe(401);

    const res = await request.get(url, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.ok()).toBeTruthy();
    const body = await res.text();
    expect(body).toContain(String(seed.finding_id));
    expect(body).toContain(seed.summary_marker);
    const parsed = JSON.parse(body) as { finding_id?: string; summary?: string }[];
    const hit = parsed.find((f) => f.finding_id === String(seed.finding_id));
    expect(hit?.summary).toBe(seed.summary_marker);
  });

  test("finding detail and task report markdown include markers", async ({ request }) => {
    const token = await login(request);
    const detail = await request.get(`/api/exploration/findings/${seed.finding_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(detail.ok()).toBeTruthy();
    const finding = await detail.json();
    expect(finding.summary).toBe(seed.summary_marker);
    expect(String(finding.report ?? "")).toContain(seed.report_marker);

    const report = await request.get(`/api/report?task=${seed.task_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(report.ok()).toBeTruthy();
    const md = await report.text();
    expect(md.length).toBeGreaterThan(80);
    expect(md).toContain(seed.summary_marker);
  });

  test("staging upload preserves fixture bytes on disk (abs path)", async ({ request }) => {
    const token = await login(request);
    const fixtureBytes = fs.readFileSync(FIXTURE);
    const expectedSha = createHash("sha256").update(fixtureBytes).digest("hex");
    if (seed.upload_fixture_sha256) {
      expect(expectedSha).toBe(seed.upload_fixture_sha256);
    }

    const stagingId = `upgrade-upload-${Date.now()}`;
    const res = await request.post(`/api/chat/upload?scope=staging&id=${stagingId}`, {
      headers: { Authorization: `Bearer ${token}` },
      multipart: {
        file: {
          name: "upload-sample.txt",
          mimeType: "text/plain",
          buffer: fixtureBytes,
        },
      },
    });
    expect(res.ok()).toBeTruthy();
    const payload = await res.json();
    const att = payload.attachments?.[0];
    expect(att?.size).toBe(fixtureBytes.length);
    expect(att?.abs).toBeTruthy();
    const onDisk = fs.readFileSync(att.abs);
    expect(createHash("sha256").update(onDisk).digest("hex")).toBe(expectedSha);
    expect(onDisk.equals(fixtureBytes)).toBe(true);

    const badScope = await request.post("/api/chat/upload?scope=task&id=999999999", {
      headers: { Authorization: `Bearer ${token}` },
      multipart: {
        file: { name: "x.txt", mimeType: "text/plain", buffer: Buffer.from("x") },
      },
    });
    expect(badScope.status()).toBe(404);
  });
});

test.describe("rendered findings export and report tabs", () => {
  const seed = loadSeed();

  test("findings page export selected + task report tab", async ({ page, request }) => {
    const token = await login(request);
    await page.addInitScript((t) => localStorage.setItem("artex_token", t), token);

    await page.goto("/function/findings");
    await expect(page.getByText(seed.summary_marker)).toBeVisible({ timeout: 20_000 });

    const row = page.locator("tr", { hasText: seed.summary_marker });
    await row.getByRole("checkbox", { name: "选择该漏洞" }).check();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: /导出/ }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByText(`导出勾选的 ${1} 条`).click();
    await page.getByRole("button", { name: /^导出$/ }).click();
    const download = await downloadPromise;
    const exportPath = await download.path();
    expect(exportPath).toBeTruthy();
    const exportBytes = fs.readFileSync(exportPath!);
    expect(exportBytes.length).toBeGreaterThan(50);
    expect(exportBytes.toString("utf8")).toContain(seed.summary_marker);

    await page.goto(`/function/tasks/detail?id=${seed.task_id}`);
    await page.getByRole("tab", { name: "报告" }).click();
    await expect(page.getByText(seed.summary_marker)).toBeVisible({ timeout: 15_000 });

    await page.goto(`/function/findings/detail?id=${seed.finding_id}`);
    await expect(page.getByText(seed.report_marker)).toBeVisible({ timeout: 15_000 });
  });
});
