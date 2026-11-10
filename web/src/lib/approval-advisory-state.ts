export interface AdvisoryResult {
  risk: "low" | "medium" | "high" | "critical" | "unknown";
  summary: string;
  consequences: string;
  recommendation: "consider_approval" | "consider_denial" | "needs_investigation";
  suggestions: string[];
}

export interface AdvisoryResponse {
  pending_id: number;
  approval_status: string;
  advisory_only: true;
  current: boolean;
  assessment: {
    state: "running" | "succeeded" | "failed" | "stale";
    fingerprint: string;
    profile_id: number;
    model: string;
    started_at: string;
    finished_at?: string | null;
    lease_until: string;
    error_code?: string;
    result?: AdvisoryResult | null;
  } | null;
}

// Both the row and response must still describe this pending request. A saved
// historical answer, even one recommending approval, never enables a decision.
export function advisoryIsCurrent(data: AdvisoryResponse | null, id: number, status: string): boolean {
  return Boolean(
    data?.pending_id === id &&
      status === "pending" &&
      data.approval_status === "pending" &&
      data.current &&
      data.assessment?.state === "succeeded" &&
      data.assessment.result,
  );
}

export function advisoryIsRunning(data: AdvisoryResponse | null, id: number, now = Date.now()): boolean {
  if (data?.pending_id !== id || data.assessment?.state !== "running") return false;
  const expiry = Date.parse(data.assessment.lease_until);
  return Number.isFinite(expiry) && expiry > now;
}
