import assert from "node:assert/strict";
import { test } from "node:test";
import { advisoryIsCurrent, advisoryIsRunning } from "../src/lib/approval-advisory-state.ts";

const saved = { pending_id: 1, approval_status: "pending", advisory_only: true, current: true,
  assessment: { state: "succeeded", result: { recommendation: "consider_approval" }, lease_until: "2030-01-01T00:00:00Z" } };
test("a current assessment is never inferred from its recommendation alone", () => {
  assert.equal(advisoryIsCurrent(saved, 1, "pending"), true);
  for (const status of ["allowed", "denied", "timeout"]) assert.equal(advisoryIsCurrent(saved, 1, status), false);
  assert.equal(advisoryIsCurrent(saved, 2, "pending"), false);
  assert.equal(advisoryIsCurrent({ ...saved, current: false }, 1, "pending"), false);
  assert.equal(advisoryIsCurrent({ ...saved, approval_status: "allowed" }, 1, "pending"), false);
  assert.equal(advisoryIsCurrent({ ...saved, assessment: { ...saved.assessment, state: "failed" } }, 1, "pending"), false);
  assert.equal(advisoryIsCurrent(null, 1, "pending"), false);
});
test("running-state polling is bounded by the saved lease and record identity", () => {
  const running = { ...saved, assessment: { ...saved.assessment, state: "running" } };
  assert.equal(advisoryIsRunning(running, 1, Date.parse("2029-01-01")), true);
  assert.equal(advisoryIsRunning(running, 1, Date.parse("2031-01-01")), false);
  assert.equal(advisoryIsRunning(running, 2, Date.parse("2029-01-01")), false);
  assert.equal(advisoryIsRunning({ ...running, assessment: { ...running.assessment, lease_until: "bad" } }, 1), false);
  assert.equal(advisoryIsRunning(saved, 1), false);
});
