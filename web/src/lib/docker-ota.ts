import { http } from "@/lib/api";
import type { UpdateChannel } from "@/lib/types";

export interface DockerOTAHistory {
  job_id?: string;
  operation?: string;
  state: string;
  message?: string;
  updated_at?: string | number;
  time?: string;
  channel?: string;
  target_revision?: string;
  target_digest?: string;
}

export interface DockerOTAStatus extends DockerOTAHistory {
  enabled: boolean;
  active: boolean;
  current_image?: string;
  previous_image?: string;
  rollback_available?: boolean;
  history?: DockerOTAHistory[];
}

export interface DockerOTAPlan {
  plan_id: string;
  channel: UpdateChannel;
  image: string;
  digest: string;
  revision: string;
  schema: string;
  rollback_safe: boolean;
  current_image?: string;
  current_revision?: string;
  expires_at: string | number;
}

const post = <T>(path: string, body: unknown) =>
  http<T>(`/update/docker/${path}`, { method: "POST", body: JSON.stringify(body) });

export const dockerOTA = {
  status: (signal?: AbortSignal) => http<DockerOTAStatus>("/update/docker/status", { signal, cache: "no-store" }),
  check: (channel: UpdateChannel) => post<DockerOTAPlan>("check", { channel }),
  apply: (planId: string) => post<DockerOTAStatus>("apply", { plan_id: planId }),
  rollback: () => post<DockerOTAStatus>("rollback", {}),
};
