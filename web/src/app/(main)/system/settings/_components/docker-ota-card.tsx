"use client";

import * as React from "react";

import { CheckCircle2Icon, DownloadIcon, RefreshCwIcon, RotateCcwIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { type DockerOTAPlan, type DockerOTAStatus, dockerOTA } from "@/lib/docker-ota";
import { dockerOTAPlanUsable, dockerOTAResult } from "@/lib/docker-ota-state";
import {
  getServerUpdateChannel,
  getUpdateChannel,
  isUpdateChannel,
  setUpdateChannel,
  subscribeUpdateChannel,
} from "@/lib/update-channel";

const phaseLabels: Record<string, string> = {
  idle: "待命",
  checking: "檢查映像檔",
  queued: "準備更新",
  verifying: "驗證簽章",
  preflight: "檢查部署相容性",
  stopping: "停止應用程式",
  backup: "備份資料庫",
  starting: "啟動目標版本",
  healthcheck: "確認服務就緒",
  completed: "更新完成",
  rolled_back: "已還原上一版本",
  failed: "更新失敗",
  recovery_required: "需要手動復原",
};

export function DockerOTACard() {
  const channel = React.useSyncExternalStore(subscribeUpdateChannel, getUpdateChannel, getServerUpdateChannel);
  const [status, setStatus] = React.useState<DockerOTAStatus | null>(null);
  const [plan, setPlan] = React.useState<DockerOTAPlan | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [now, setNow] = React.useState(Date.now());
  const request = React.useRef(0);
  const observed = React.useRef<string | null>(null);
  const mounted = React.useRef<boolean>(true);
  const selectedChannel = React.useRef(channel);

  React.useEffect(() => {
    if (selectedChannel.current === channel) return;
    selectedChannel.current = channel;
    request.current++;
    setPlan(null);
    setChecking(false);
  }, [channel]);

  React.useEffect(() => {
    mounted.current = true;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    let controller: AbortController;
    const poll = async () => {
      controller = new AbortController();
      try {
        const result = await dockerOTA.status(controller.signal);
        if (stopped) return;
        setStatus(result);
        setError(null);
        const identity = `${result.job_id ?? ""}:${result.state}`;
        if (observed.current !== null && observed.current !== identity && result.job_id) {
          const outcome = dockerOTAResult(result.state);
          if (outcome === "success") {
            toast.success("Docker 映像檔更新完成，服務已通過就緒檢查");
            setPlan(null);
          } else if (outcome === "rollback") {
            toast.message("更新服務已還原上一個映像檔，請查看更新紀錄");
            setPlan(null);
          } else if (outcome === "failure") {
            toast.error(result.message ?? phaseLabels[result.state]);
          }
        }
        observed.current = identity;
      } catch (cause) {
        if (stopped) return;
        setError(cause instanceof Error ? cause.message : "無法讀取 Docker 更新狀態");
      }
      if (!stopped) {
        setNow(Date.now());
        timer = setTimeout(poll, 3000);
      }
    };
    void poll();
    return () => {
      stopped = true;
      mounted.current = false;
      request.current++;
      clearTimeout(timer);
      controller?.abort();
    };
  }, []);

  const check = async () => {
    const sequence = ++request.current;
    setChecking(true);
    setPlan(null);
    try {
      const next = await dockerOTA.check(channel);
      if (!mounted.current || sequence !== request.current || channel !== getUpdateChannel()) return;
      setPlan(next);
      setNow(Date.now());
      toast.success("目標映像檔已固定，請確認提交與更新影響");
    } catch (cause) {
      if (mounted.current && sequence === request.current) {
        toast.error(cause instanceof Error ? cause.message : "Docker 更新檢查失敗");
      }
    } finally {
      if (mounted.current && sequence === request.current) setChecking(false);
    }
  };

  const submit = async (rollback: boolean) => {
    if (submitting || status?.active || (rollback ? !status?.rollback_available : !dockerOTAPlanUsable(plan, channel)))
      return;
    const target = rollback ? status?.previous_image : plan?.image;
    if (
      !window.confirm(
        `${rollback ? "還原" : "安裝"} Docker 映像檔？\n${target ?? ""}\n\n` +
          "更新會短暫中斷服務。請先暫停或完成所有任務，並等待 Agent 對話結束。" +
          "更新服務會先備份資料庫；若目標版本啟動後失敗，可能需要手動復原。",
      )
    )
      return;
    setSubmitting(true);
    try {
      let next: DockerOTAStatus;
      if (rollback) next = await dockerOTA.rollback();
      else if (plan) next = await dockerOTA.apply(plan.plan_id);
      else return;
      if (!mounted.current) return;
      setStatus(next);
      setPlan(null);
      toast.message("已提交更新工作，重新連線後會繼續顯示進度");
    } catch (cause) {
      if (mounted.current) toast.error(cause instanceof Error ? cause.message : "無法提交更新，請查看更新狀態");
    } finally {
      if (mounted.current) setSubmitting(false);
    }
  };

  const active = Boolean(status?.active) || submitting;
  const failed = status?.state === "failed" || status?.state === "recovery_required";
  const planUsable = dockerOTAPlanUsable(plan, channel, now);

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <DownloadIcon className="size-4" /> Docker 映像檔更新
        </CardTitle>
        <CardDescription>由主機更新服務安裝已驗證的完整映像檔，包含 ARTEX 與工具鏈。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {status && !status.enabled ? (
          <p className="text-muted-foreground text-sm">
            尚未啟用 Docker OTA。請依部署文件在主機設定更新服務，完成一次遷移後即可從這裡更新。
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={failed ? "destructive" : "secondary"}>
                {status ? (phaseLabels[status.state] ?? status.state) : "讀取狀態中"}
              </Badge>
              {active && <RefreshCwIcon aria-label="更新進行中" className="size-4 animate-spin" />}
            </div>
            {status?.current_image && (
              <p className="text-muted-foreground font-mono text-xs break-all">目前映像檔：{status.current_image}</p>
            )}
            <Select
              value={channel}
              onValueChange={(value) => {
                if (isUpdateChannel(value) && value !== channel) {
                  request.current++;
                  setPlan(null);
                  setUpdateChannel(value);
                }
              }}
              disabled={active}
            >
              <SelectTrigger aria-label="Docker 更新通道">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="stable">Stable 正式版</SelectItem>
                <SelectItem value="nightly">Nightly 預發布版</SelectItem>
                <SelectItem value="main">Main 最新建置</SelectItem>
              </SelectContent>
            </Select>
            {plan && (
              <div className="space-y-2 rounded-md border p-3 text-xs">
                <p className="flex items-center gap-2">
                  <CheckCircle2Icon className="size-4 text-emerald-600" /> 已固定目標映像檔
                </p>
                <p className="font-mono break-all">{plan.image}</p>
                <p className="font-mono break-all">提交：{plan.revision}</p>
                <p>更新不會變更 PostgreSQL 主版本。啟動新版本後不會自動還原資料庫備份。</p>
                <p>
                  {plan.rollback_safe
                    ? "資料格式指紋相同；新版本未通過就緒檢查時，可自動還原目前映像檔。"
                    : "資料格式指紋不同或尚未確認；新版本啟動後若失敗，需要主機管理員復原。"}
                </p>
                {!planUsable && <p className="text-destructive">更新計畫已過期，請重新檢查更新。</p>}
              </div>
            )}
            {status?.message && (
              <p className="text-sm" role="status">
                {status.message}
              </p>
            )}
            {status?.state === "recovery_required" && (
              <p className="text-destructive text-sm">
                服務仍處於維護狀態。請由主機管理員查看更新紀錄與備份，完成復原後解除維護。
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => void check()}
                disabled={!status?.enabled || active || checking}
              >
                <RefreshCwIcon className={checking ? "size-4 animate-spin" : "size-4"} /> 檢查映像檔
              </Button>
              <Button
                size="sm"
                onClick={() => void submit(false)}
                disabled={active || checking || !planUsable || status?.state === "recovery_required"}
              >
                <DownloadIcon className="size-4" /> 安裝此版本
              </Button>
              {status?.rollback_available && (
                <Button variant="outline" size="sm" onClick={() => void submit(true)} disabled={active || checking}>
                  <RotateCcwIcon className="size-4" /> 還原上一映像檔
                </Button>
              )}
            </div>
            {(status?.history?.length ?? 0) > 0 && (
              <details className="text-xs">
                <summary className="text-muted-foreground cursor-pointer">最近更新紀錄</summary>
                <ul className="mt-2 space-y-2">
                  {status?.history?.map((item, index) => (
                    <li
                      key={`${item.job_id ?? index}:${item.state}:${item.time ?? item.updated_at ?? ""}`}
                      className="rounded-md border p-2"
                    >
                      <span>{phaseLabels[item.state] ?? item.state}</span>
                      {item.time && (
                        <time className="text-muted-foreground ml-2">{new Date(item.time).toLocaleString()}</time>
                      )}
                      {item.target_revision && (
                        <p className="mt-1 font-mono break-all">
                          {item.channel} · {item.target_revision}
                        </p>
                      )}
                      {item.message && <p className="text-muted-foreground mt-1">{item.message}</p>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )}
        {error && (
          <p className="text-destructive flex items-start gap-2 text-xs" role="alert">
            <TriangleAlertIcon className="size-4 shrink-0" />
            {error}。切換容器時可能暫時中斷連線，頁面會自動重試；連線恢復不代表更新成功。
          </p>
        )}
      </CardContent>
    </Card>
  );
}
