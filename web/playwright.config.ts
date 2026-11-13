import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:8787";
const useExternalBase = process.env.PLAYWRIGHT_BASE_URL != null && process.env.PLAYWRIGHT_BASE_URL !== "";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "e2e/playwright-report" }]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: useExternalBase
    ? undefined
    : {
        command: "bash e2e/bin/start-backend.sh",
        url: `${baseURL.replace(/\/$/, "")}/api/health`,
        reuseExistingServer: false,
        timeout: 600_000,
        cwd: __dirname,
      },
});
