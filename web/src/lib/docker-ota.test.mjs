import assert from "node:assert/strict";
import test from "node:test";
import { dockerOTAPlanUsable, dockerOTAResult } from "./docker-ota-state.ts";

test("only updater terminal states establish the result", () => {
  for (const state of ["idle", "queued", "starting", "healthcheck", "reachable", "verifying"]) {
    assert.equal(dockerOTAResult(state), null);
  }
  assert.equal(dockerOTAResult("completed"), "success");
  assert.equal(dockerOTAResult("rolled_back"), "rollback");
  assert.equal(dockerOTAResult("failed"), "failure");
  assert.equal(dockerOTAResult("recovery_required"), "failure");
});

test("expired, invalid, or different-channel plans cannot install", () => {
  const now = Date.parse("2026-11-26T00:00:00Z");
  const plan = { channel: "main", expires_at: now / 1000 + 60 };
  assert.equal(dockerOTAPlanUsable(plan, "main", now), true);
  assert.equal(dockerOTAPlanUsable(plan, "nightly", now), false);
  assert.equal(dockerOTAPlanUsable(plan, "main", now + 60000), false);
  assert.equal(dockerOTAPlanUsable({ ...plan, expires_at: "invalid" }, "main", now), false);
  assert.equal(dockerOTAPlanUsable(null, "main", now), false);
  assert.equal(dockerOTAPlanUsable({ ...plan, expires_at: "2026-11-26T00:01:00Z" }, "main", now), true);
});
