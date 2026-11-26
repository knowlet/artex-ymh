// Success is an explicit updater result, never just a reachable health URL or a
// changed version string. This also works when two builds share the same tag.
export function dockerOTAResult(state: string): "success" | "rollback" | "failure" | null {
  if (state === "completed") return "success";
  if (state === "rolled_back") return "rollback";
  if (state === "failed" || state === "recovery_required") return "failure";
  return null;
}

export function dockerOTAExpiry(value: string | number): number {
  return typeof value === "number" ? value * 1000 : Date.parse(value);
}

export function dockerOTAPlanUsable(
  plan: { channel: string; expires_at: string | number } | null,
  channel: string,
  now = Date.now(),
): boolean {
  return plan !== null && plan.channel === channel && dockerOTAExpiry(plan.expires_at) > now;
}
