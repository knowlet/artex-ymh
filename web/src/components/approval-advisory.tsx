"use client";

import * as React from "react";
import { Loader2Icon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getApprovalAdvisory, requestApprovalAdvisory } from "@/lib/approval-advisory";
import { cancelApprovalAdvisoryAuto } from "@/lib/approval-advisory-auto";
import { type AdvisoryResponse, advisoryIsCurrent, advisoryIsRunning } from "@/lib/approval-advisory-state";
import { MOCK } from "@/lib/mock/enabled";

const riskLabels = { low: "低", medium: "中", high: "高", critical: "極高", unknown: "無法判定" };
const recommendationLabels = {
  consider_approval: "可供人工考慮核准（並非授權）",
  consider_denial: "建議人工拒絕",
  needs_investigation: "建議先補充查證",
};
const errorLabels: Record<string, string> = {
  timeout: "模型逾時",
  cancelled: "審查已取消",
  interrupted: "審查中斷或服務重新啟動",
  provider_unavailable: "裁判模型不可用",
  policy_unavailable: "無法確認最新政策或模型設定",
  invalid_response: "模型回應不完整或格式不符",
  review_failed: "審查失敗",
  snapshot_changed: "審批或政策已改變",
};

function advisoryNeedsPoll(data: AdvisoryResponse | null, id: number, status: string, current: boolean): boolean {
  if (status !== "pending" || data?.pending_id !== id) return false;
  if (advisoryIsRunning(data, id)) return true;
  if (data.auto_queued) return true;
  return Boolean(data.auto_enabled && !data.auto_cancelled && !current);
}

export function ApprovalAdvisory({ id, status, readOnly = false }: { id: number; status: string; readOnly?: boolean }) {
  const [data, setData] = React.useState<AdvisoryResponse | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [reload, setReload] = React.useState(0);
  const generation = React.useRef(0);
  const lifetime = React.useRef<AbortController | null>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: explicit reload restarts the saved-state GET loop.
  React.useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    const ownGeneration = ++generation.current;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setData(null);
    setError("");
    setBusy(false);
    async function load() {
      try {
        const next = await getApprovalAdvisory(id, controller.signal);
        if (controller.signal.aborted || generation.current !== ownGeneration) return;
        setData(next);
        const current = advisoryIsCurrent(next, id, status);
        if (advisoryNeedsPoll(next, id, status, current)) {
          timer = setTimeout(() => void load(), 2000);
        }
      } catch (e) {
        if (!controller.signal.aborted && generation.current === ownGeneration) setError((e as Error).message);
      }
    }
    void load();
    return () => {
      controller.abort();
      clearTimeout(timer);
      generation.current++;
    };
  }, [id, status, reload]);

  const running = busy || advisoryIsRunning(data, id);
  const current = advisoryIsCurrent(data, id, status);
  const assessment = data?.pending_id === id ? data.assessment : null;

  async function review() {
    if (running || readOnly || status !== "pending" || MOCK) return;
    const controller = lifetime.current;
    if (!controller || controller.signal.aborted) return;
    const ownGeneration = generation.current;
    setBusy(true);
    setError("");
    try {
      const next = await requestApprovalAdvisory(id, controller.signal);
      if (!controller.signal.aborted && ownGeneration === generation.current) {
        setData(next);
        setReload((n) => n + 1);
      }
    } catch (e) {
      if (!controller.signal.aborted && ownGeneration === generation.current) setError((e as Error).message);
    } finally {
      if (!controller.signal.aborted && ownGeneration === generation.current) setBusy(false);
    }
  }

  async function cancelAuto() {
    if (readOnly || MOCK || !data?.auto_enabled) return;
    try {
      await cancelApprovalAdvisoryAuto(id);
      setReload((n) => n + 1);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <section aria-label="智慧審查建議" className="flex min-w-0 flex-col gap-3 rounded-xl border p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="font-medium text-sm">智慧審查建議</h3>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" disabled={running} onClick={() => setReload((n) => n + 1)}>更新狀態</Button>
          {!readOnly && data?.auto_enabled && status === "pending" && !data.auto_cancelled ? (
            <Button variant="ghost" size="sm" onClick={() => void cancelAuto()}>停止自動重試</Button>
          ) : null}
          {!readOnly && status === "pending" ? (
          <Button variant="outline" size="sm" disabled={running || current || MOCK} onClick={() => void review()}>
            {running ? <Loader2Icon aria-hidden="true" className="animate-spin" /> : null}
            {running ? "審查中" : current ? "已保存審查" : assessment ? "手動重新審查" : "手動審查"}
          </Button>
          ) : null}
        </div>
      </div>
      <p className="text-muted-foreground text-xs leading-6">
        僅提供風險建議，不會核准、拒絕或執行工具，也不會延長原審批期限。背景審查（若已啟用）與手動審查皆會把命令、已選取背景與政策送至裁判模型，可能產生費用；內容可能含敏感資料。
      </p>
      {data?.auto_enabled && !data.auto_cancelled ? (
        <p className="text-muted-foreground text-xs">背景自動審查已啟用：新待審批會自動排程，仍須人工核准／拒絕。</p>
      ) : null}
      {data?.auto_cancelled ? (
        <p className="text-muted-foreground text-xs">
          此筆已停止自動重試；可手動審查或人工決定。不會中斷進行中的模型請求；若推理已完成，結果不會成為目前建議。
        </p>
      ) : null}
      {MOCK ? <p className="text-muted-foreground text-xs">演示模式不呼叫模型。</p> : null}
      <div role="status" aria-live="polite" className="text-sm">
        {data?.auto_queued && !running ? "已加入背景審查佇列，無需手動點擊。" : null}
        {running ? "正在分析；人工核准／拒絕仍可獨立操作。" : null}
        {error ? <p className="text-destructive">{error}。未變更審批結果。</p> : null}
        {assessment?.state === "failed" || assessment?.state === "stale" ? (
          <p>{errorLabels[assessment.error_code || ""] || "無可用審查結論"}。不代表操作安全，請人工判斷。</p>
        ) : null}
        {assessment?.result ? (
          <div className="flex flex-col gap-3">
            {!current ? <p className="font-medium">歷史建議／快照已失效：不可視為目前操作的授權。</p> : null}
            <p>風險：{riskLabels[assessment.result.risk]} · {recommendationLabels[assessment.result.recommendation]}</p>
            <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{assessment.result.summary}</p>
            <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">成功後影響：{assessment.result.consequences}</p>
            <div className="flex flex-col gap-2">
              {assessment.result.suggestions.map((text, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: immutable, ordered snapshot entries can repeat.
                <p key={index} className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{index + 1}. {text}</p>
              ))}
            </div>
          </div>
        ) : null}
      </div>
      {assessment ? (
        <p className="text-muted-foreground text-xs">
          裁判設定 #{assessment.profile_id} · {assessment.model}
          {assessment.trigger === "auto" ? " · 背景自動" : ""}
          {" · "}{new Date(assessment.finished_at || assessment.started_at).toLocaleString("zh-TW")}
        </p>
      ) : null}
    </section>
  );
}
