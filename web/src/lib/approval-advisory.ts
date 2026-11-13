import { http } from "@/lib/api";
import type { AdvisoryResponse } from "@/lib/approval-advisory-state";
import { MOCK } from "@/lib/mock/enabled";

export function getApprovalAdvisory(id: number, signal?: AbortSignal): Promise<AdvisoryResponse> {
  if (MOCK) {
    return Promise.resolve({ pending_id: id, approval_status: "pending", advisory_only: true, current: false, assessment: null });
  }
  return http<AdvisoryResponse>(`/intercept/pending/${id}/advisory`, { signal });
}

// This is called only from the explicit UI click, never from mount or polling.
export function requestApprovalAdvisory(id: number, signal?: AbortSignal): Promise<AdvisoryResponse> {
  if (MOCK) return Promise.reject(new Error("演示模式不呼叫裁判模型"));
  return http<AdvisoryResponse>(`/intercept/pending/${id}/advisory`, { method: "POST", body: "{}", signal });
}
