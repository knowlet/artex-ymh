const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const ts = require("typescript");

// Load the real configs, keeping each environment probe independent of Node's cache.
function loadConfig(filename, env = {}) {
  const previous = {};
  for (const key of ["PLAYWRIGHT_BASE_URL", "ADVISORY_E2E_WEB_URL", "CI"]) {
    previous[key] = process.env[key];
    if (env[key] === undefined) delete process.env[key];
    else process.env[key] = env[key];
  }
  try {
    const fullPath = path.join(__dirname, filename);
    const compiled = ts.transpileModule(fs.readFileSync(fullPath, "utf8"), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    });
    const mod = new Module(fullPath, module);
    mod.filename = fullPath;
    mod.paths = module.paths;
    mod._compile(compiled.outputText, fullPath);
    return mod.exports.default;
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function listedSpecs(config) {
  // --list collects real test files without starting a server, browser, or provider.
  const run = spawnSync(
    process.execPath,
    [require.resolve("@playwright/test/cli"), "test", "--config", config, "--list", "--reporter=json"],
    { cwd: __dirname, encoding: "utf8" },
  );
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const report = JSON.parse(run.stdout);
  assert.deepEqual(report.errors, []);
  return report.suites.map((suite) => path.basename(suite.file)).sort();
}

test("default reproduction config retains its managed backend", () => {
  const config = loadConfig("playwright.config.ts");
  assert.equal(config.use.baseURL, "http://127.0.0.1:8787");
  assert.equal(config.webServer.command, "bash e2e/bin/start-backend.sh");
  assert.equal(config.webServer.url, "http://127.0.0.1:8787/api/health");
  assert.equal(config.webServer.reuseExistingServer, false);
});

test("external reproduction URL does not start a local backend", () => {
  const config = loadConfig("playwright.config.ts", {
    PLAYWRIGHT_BASE_URL: " http://127.0.0.1:9876/ ",
    ADVISORY_E2E_WEB_URL: "http://127.0.0.1:3001",
  });
  assert.equal(config.use.baseURL, "http://127.0.0.1:9876/");
  assert.equal(config.webServer, undefined);
});

test("advisory config only uses its separately managed fake-provider harness", () => {
  const config = loadConfig("playwright.advisory.config.ts", {
    PLAYWRIGHT_BASE_URL: "http://127.0.0.1:9876",
    ADVISORY_E2E_WEB_URL: "http://127.0.0.1:3001",
  });
  assert.equal(config.use.baseURL, "http://127.0.0.1:3001");
  assert.equal(config.webServer, undefined);
  assert.equal(loadConfig("playwright.advisory.config.ts").use.baseURL, "http://127.0.0.1:3000");
});

test("real Playwright discovery keeps both browser suites disjoint", () => {
  const reproduction = listedSpecs("playwright.config.ts");
  const advisory = listedSpecs("playwright.advisory.config.ts");
  assert.ok(reproduction.includes("findings-reproduction.spec.ts"));
  assert.ok(!reproduction.includes("advisory-auto.spec.ts"));
  assert.deepEqual(advisory, ["advisory-auto.spec.ts"]);
});

test("both advisory entry points choose the dedicated config", () => {
  const scripts = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8")).scripts;
  assert.equal(scripts["e2e:advisory"], "playwright test -c playwright.advisory.config.ts");
  const runner = fs.readFileSync(path.join(__dirname, "../scripts/e2e-advisory.sh"), "utf8");
  assert.match(runner, /npx playwright test -c playwright\.advisory\.config\.ts --reporter=list/);
});
