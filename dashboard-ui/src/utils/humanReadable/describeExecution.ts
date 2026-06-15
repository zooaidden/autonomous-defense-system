// Convert an ExecutionRecord (actuator-service execution log) into a human
// timeline-friendly descriptor. The result is consumed by a Disclosure row in
// the strategy-execution page so the table can stay compact yet expandable.

import type { ExecutionRecord } from "../../types";
import { statusZh } from "./zh/status";

export interface ExecutionDescriptor {
  executionId: string;
  strategyId: string;
  statusText: string;
  statusTone: "ok" | "warn" | "danger" | "neutral";
  rollbackText: string;
  rollbackTone: "ok" | "warn" | "danger" | "neutral";
  startedAt: string;
  endedAt: string;
  durationText: string;
  ttlText: string;
  resultMessage: string;
  failureReason?: string;
}

function classifyStatus(status: string): { text: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  const up = status.toUpperCase();
  if (up === "SUCCEEDED" || up === "SUCCESS")
    return { text: statusZh(up), tone: "ok" };
  if (up === "FAILED" || up === "RUNTIME_ERROR" || up === "TIMEOUT" || up === "BLOCKED")
    return { text: statusZh(up), tone: "danger" };
  if (up === "PENDING_APPROVAL" || up === "REQUIRES_APPROVAL" || up === "SKIPPED")
    return { text: statusZh(up), tone: "warn" };
  return { text: status || "—", tone: "neutral" };
}

function classifyRollback(value: string): { text: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  if (!value) return { text: "—", tone: "neutral" };
  const up = value.toUpperCase();
  if (up === "SUCCEEDED") return { text: "已回滚", tone: "ok" };
  if (up === "AVAILABLE") return { text: "可回滚", tone: "warn" };
  if (up === "FAILED") return { text: "回滚失败", tone: "danger" };
  if (up === "UNAVAILABLE" || up === "NONE") return { text: "无回滚窗口", tone: "neutral" };
  return { text: value, tone: "neutral" };
}

function formatTime(value: string | undefined | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function formatDuration(start?: string, end?: string): string {
  if (!start || !end) return "—";
  const s = new Date(start).getTime();
  const e = new Date(end).getTime();
  if (Number.isNaN(s) || Number.isNaN(e) || e < s) return "—";
  const sec = Math.round((e - s) / 1000);
  if (sec <= 0) return "<1 秒";
  if (sec < 60) return `${sec} 秒`;
  const min = Math.floor(sec / 60);
  return `${min} 分 ${sec - min * 60} 秒`;
}

export function describeExecutionHuman(record: ExecutionRecord): ExecutionDescriptor {
  const status = classifyStatus(record.status ?? "");
  const rollback = classifyRollback(record.rollbackStatus ?? "");
  const ttl = typeof record.ttl === "number" ? record.ttl : Number(record.ttl ?? 0);
  return {
    executionId: record.executionId,
    strategyId: record.strategyId,
    statusText: status.text,
    statusTone: status.tone,
    rollbackText: rollback.text,
    rollbackTone: rollback.tone,
    startedAt: formatTime(record.startTime),
    endedAt: formatTime(record.endTime),
    durationText: formatDuration(record.startTime, record.endTime),
    ttlText: ttl > 0 ? `${Math.round(ttl / 60)} 分钟` : "—",
    resultMessage: record.resultMessage || "—",
    failureReason: record.failureReason ?? undefined,
  };
}
