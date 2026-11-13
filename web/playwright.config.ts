import { defineConfig, devices } from "@playwright/test";

const externalBase = process.env.PLAYWRIGHT_BASE_URL?.trim() ?? "";
const useExternalBase = externalBase !== "";
const baseURL = useExternalBase ? externalBase : "http://127.0.0.1:8787";
const healthURL = useExternalBase
  ? `${baseURL.replace(/\/$/, "")}/api/health`
  : "http://127.0.0.1:8787/api/health";

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
        url: healthURL,
        reuseExistingServer: false,
        timeout: 600_000,
        cwd: __dirname,
      },
});
