"use client";

import * as React from "react";

import { ExternalLinkIcon, Loader2Icon, LogOutIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { XAIOAuthLogin, XAIOAuthStatus } from "@/lib/types";
import { safeXAIAuthURL } from "@/lib/xai-oauth";

export function XAIOAuthPanel({
  status,
  onRefresh,
}: {
  status: XAIOAuthStatus | null;
  onRefresh: () => Promise<void>;
}) {
  const [flow, setFlow] = React.useState<XAIOAuthLogin | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const alive = React.useRef(false);
  const pendingID = React.useRef<string | null>(null);
  const generation = React.useRef(0);

  React.useEffect(() => {
    alive.current = true;
    void onRefresh();
    return () => {
      alive.current = false;
      generation.current += 1;
      const id = pendingID.current;
      pendingID.current = null;
      if (id) void api.cancelXAIOAuthLogin(id).catch(() => undefined);
    };
  }, [onRefresh]);

  React.useEffect(() => {
    if (!flow) return;
    const activeFlow = flow;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const currentGeneration = generation.current;
    const delay = Number.isFinite(flow.interval) ? Math.max(2, flow.interval) * 1000 : 5000;
    const isCurrent = () => !cancelled && alive.current && currentGeneration === generation.current;

    async function poll() {
      try {
        const result = await api.xaiOAuthLoginState(activeFlow.flow_id);
        if (!isCurrent()) return;
        if (result.state === "pending") {
          setError("");
        } else {
          pendingID.current = null;
          setFlow(null);
          if (result.state === "complete") {
            setError("");
            toast.success("Grok 订阅登录完成；可测试连接并保存配置");
          } else {
            const fallback = result.state === "expired" ? "授权已过期，请重新登录。" : "授权已取消或未完成。";
            setError(result.error || fallback);
          }
          await onRefresh();
          return;
        }
      } catch (e) {
        if (!isCurrent()) return;
        setError(`暂时无法确认登录状态：${(e as Error).message}`);
        // A lost polling response is not proof that authorization failed. Keep
        // checking within the bounded device-code lifetime; cancellation remains available.
        if (Date.now() > Date.parse(activeFlow.expires_at) + 10_000) {
          pendingID.current = null;
          setFlow(null);
          void api.cancelXAIOAuthLogin(activeFlow.flow_id).catch(() => undefined);
          return;
        }
      }
      if (isCurrent()) timer = setTimeout(() => void poll(), delay);
    }

    timer = setTimeout(() => void poll(), delay);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [flow, onRefresh]);

  async function start() {
    if (busy || pendingID.current) return;
    setBusy(true);
    setError("");
    const currentGeneration = ++generation.current;
    try {
      const next = await api.startXAIOAuthLogin();
      if (!alive.current || generation.current !== currentGeneration) {
        await api.cancelXAIOAuthLogin(next.flow_id);
        return;
      }
      if (
        !(safeXAIAuthURL(next.verification_uri_complete) ?? safeXAIAuthURL(next.verification_uri)) ||
        !Number.isFinite(Date.parse(next.expires_at))
      ) {
        await api.cancelXAIOAuthLogin(next.flow_id);
        throw new Error("授权服务返回了无效的验证链接或期限，请重试。");
      }
      pendingID.current = next.flow_id;
      setFlow(next);
    } catch (e) {
      if (alive.current && generation.current === currentGeneration) setError((e as Error).message);
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  async function cancel() {
    const id = pendingID.current;
    if (!id || busy) return;
    setBusy(true);
    generation.current += 1;
    try {
      await api.cancelXAIOAuthLogin(id);
      pendingID.current = null;
      if (alive.current) {
        setFlow(null);
        setError("");
        await onRefresh();
      }
    } catch (e) {
      if (alive.current) {
        setError(`取消失败，请重试：${(e as Error).message}`);
        setFlow((current) => (current ? { ...current } : null));
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  async function logout() {
    if (busy || pendingID.current) return;
    setBusy(true);
    setError("");
    try {
      await api.logoutXAIOAuth();
      await onRefresh();
      if (alive.current) {
        toast.success("已登出，此实例的 Grok 订阅配置需要重新登录");
      }
    } catch (e) {
      if (alive.current) setError(`登出失败：${(e as Error).message}`);
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  const connected = status?.connected && !status.reauth_required;
  let statusLabel = "登录状态未知";
  if (status) statusLabel = connected ? "已登录" : "未登录";
  if (status?.reauth_required) statusLabel = "需要重新登录";
  const verificationLink = flow
    ? (safeXAIAuthURL(flow.verification_uri_complete) ?? safeXAIAuthURL(flow.verification_uri))
    : undefined;

  return (
    <section className="grid gap-3 rounded-lg border p-3" aria-label="Grok 订阅登录">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium text-sm">Grok 订阅（OAuth）</span>
        <Badge variant="outline">{statusLabel}</Badge>
      </div>
      <p className="text-muted-foreground text-xs">
        使用 SuperGrok / X Premium+ 账号在 xAI 官方页面授权。此 ARTEX 实例的全部 Grok 订阅配置共享登录账号，
        凭证仅保存在服务器。可用模型和额度由 xAI 决定；额度不足时不会自动切换至按量计费的 API Key。
      </p>

      {flow && verificationLink ? (
        <div className="grid gap-2 rounded-md bg-muted p-3" role="status">
          <p className="text-sm">打开验证页面，登录并核对授权码：</p>
          <code className="select-all break-all font-mono font-semibold text-lg">{flow.user_code}</code>
          <a
            href={verificationLink}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-primary text-sm underline underline-offset-4"
          >
            前往 xAI 验证 <ExternalLinkIcon className="size-3.5" />
          </a>
          <p className="text-muted-foreground text-xs">有效至 {new Date(flow.expires_at).toLocaleString()}</p>
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1 text-muted-foreground text-xs">
              <Loader2Icon className="size-3.5 animate-spin" /> 等待浏览器授权…
            </span>
            <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void cancel()}>
              取消登录
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void start()}>
            {busy && <Loader2Icon className="animate-spin" />}
            {connected ? "重新登录 / 切换账号" : "登录 Grok 订阅"}
          </Button>
          <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void onRefresh()}>
            <RefreshCwIcon /> 刷新状态
          </Button>
          {(status?.connected || status?.reauth_required) && (
            <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void logout()}>
              <LogOutIcon /> 登出此实例
            </Button>
          )}
        </div>
      )}
      {error && (
        <p role="alert" className="break-words text-destructive text-xs">
          {error}
        </p>
      )}
      {!connected && <p className="text-muted-foreground text-xs">可以先保存配置；登录后再测试连接与启用。</p>}
    </section>
  );
}
