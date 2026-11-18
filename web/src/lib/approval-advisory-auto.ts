import { http } from "@/lib/api";

export interface AdvisoryAutoConfig {
  enabled: boolean;
  consent_at?: string;
  global_slots: number;
  max_retries: number;
  daily_budget: number;
  daily_used: number;
  ready: boolean;
  consent_given: boolean;
}

export function getAdvisoryAutoConfig(): Promise<AdvisoryAutoConfig> {
  return http<AdvisoryAutoConfig>("/intercept/advisory-auto");
}

export function setAdvisoryAutoConfig(cfg: AdvisoryAutoConfig & { consent_at: string }): Promise<AdvisoryAutoConfig> {
  return http<AdvisoryAutoConfig>("/intercept/advisory-auto", { method: "PUT", body: JSON.stringify(cfg) });
}

export function cancelApprovalAdvisoryAuto(id: number): Promise<unknown> {
  return http(`/intercept/pending/${id}/advisory/cancel`, { method: "POST", body: "{}" });
}
