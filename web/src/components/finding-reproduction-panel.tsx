"use client";

import * as React from "react";
import Link from "next/link";

import { ExternalLinkIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { FindingReproduction, ReproStep } from "@/lib/types";

function StepBlock({ step, index }: { step: ReproStep; index: number }) {
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
        <span>步骤 {index + 1}</span>
        {step.expected ? <span className="text-muted-foreground font-normal">预期：{step.expected}</span> : null}
        {step.proves ? <span className="text-muted-foreground font-normal">证明：{step.proves}</span> : null}
      </div>
      {step.request ? (
        <pre className="max-h-48 overflow-auto rounded bg-muted px-2 py-1.5 font-mono text-xs whitespace-pre-wrap">{step.request}</pre>
      ) : null}
      {step.response ? (
        <>
          <p className="text-xs text-muted-foreground">响应</p>
          <pre className="max-h-36 overflow-auto rounded bg-muted px-2 py-1.5 font-mono text-xs whitespace-pre-wrap">{step.response}</pre>
        </>
      ) : null}
      {step.exchange_id ? (
        <Button asChild variant="outline" size="sm" className="h-7 gap-1">
          <Link href={`/function/traffic?id=${encodeURIComponent(step.exchange_id)}`}>
            <ExternalLinkIcon className="size-3.5" />
            查看流量包 {step.exchange_id}
          </Link>
        </Button>
      ) : null}
    </div>
  );
}

export function FindingReproductionPanel({ repro }: { repro?: FindingReproduction | null }) {
  if (!repro) return null;
  const hasSteps = (repro.steps?.length ?? 0) > 0;
  if (!hasSteps && !repro.entry_point && !(repro.prerequisites?.length ?? 0)) {
    return null;
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">结构化复现过程</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {repro.entry_point ? (
          <p>
            <span className="text-muted-foreground">入口点：</span>
            <code className="break-all font-mono text-xs">{repro.entry_point}</code>
          </p>
        ) : null}
        {(repro.prerequisites?.length ?? 0) > 0 ? (
          <div>
            <p className="text-muted-foreground mb-1">前置条件</p>
            <ul className="ml-4 list-disc">
              {repro.prerequisites!.map((p, i) => (
                <li key={i}>{p}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {hasSteps ? <div className="space-y-2">{repro.steps!.map((st, i) => <StepBlock key={i} step={st} index={i} />)}</div> : null}
        {repro.provenance ? (
          <p className="text-xs text-muted-foreground">
            来源：<span className="text-foreground">{repro.provenance}</span>
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
