import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  use: {
    baseURL: process.env.ARTEX_E2E_BASE_URL ?? "http://127.0.0.1:8787",
    trace: "on-first-retry",
  },
  reporter: [["list"], ["json", { outputFile: "../evidence/playwright-report.json" }]],
});
