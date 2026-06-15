// Convert a SecurityEvent into a row/detail-friendly descriptor and a
// disposition-status chip that the EventListPage can render alongside the
// TaskStore-derived state. Keeps all enum localization in one place.

import type { SecurityEvent } from "../../types";
import { severityZh } from "./zh/risk";
import { sourceTypeZh } from "./zh/threat";
import { eventActionZh } from "./zh/action";

export type DispositionStatus =
  | "untouched"
  | "processing"
  | "resolved"
  | "blocked"
  | "failed"
  | "needs-approval";

export interface DispositionChip {
  status: DispositionStatus;
  label: string;
  tone: "neutral" | "info" | "ok" | "warn" | "danger";
}

export interface EventRowDescriptor {
  id: string;
  eventId: string;
  timestamp: string;
  timestampDisplay: string;
  sourceText: string;
  actionText: string;
  severityText: string;
  severityTone: "ok" | "warn" | "danger" | "neutral";
  riskScore: number;
  riskBarPct: number;
}

function formatTime(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function severityTone(value: string): "ok" | "warn" | "danger" | "neutral" {
  const up = value.toUpperCase();
  if (up === "CRITICAL" || up === "HIGH") return "danger";
  if (up === "MEDIUM") return "warn";
  if (up === "LOW") return "ok";
  return "neutral";
}

export function describeSecurityEventRow(event: SecurityEvent): EventRowDescriptor {
  return {
    id: event.id,
    eventId: event.eventId,
    timestamp: event.timestamp,
    timestampDisplay: formatTime(event.timestamp),
    sourceText: sourceTypeZh(event.sourceType),
    actionText: eventActionZh(event.action),
    severityText: severityZh(event.severity),
    severityTone: severityTone(event.severity),
    riskScore: event.riskScore,
    riskBarPct: Math.round(Math.max(0, Math.min(1, event.riskScore)) * 100),
  };
}

export const DISPOSITION_LABEL: Record<DispositionStatus, string> = {
  untouched: "未处置",
  processing: "处置中",
  resolved: "已处置",
  blocked: "已阻断",
  failed: "处置失败",
  "needs-approval": "需审批",
};

export const DISPOSITION_TONE: Record<DispositionStatus, DispositionChip["tone"]> = {
  untouched: "neutral",
  processing: "info",
  resolved: "ok",
  blocked: "warn",
  failed: "danger",
  "needs-approval": "warn",
};

export function dispositionChip(status: DispositionStatus): DispositionChip {
  return {
    status,
    label: DISPOSITION_LABEL[status],
    tone: DISPOSITION_TONE[status],
  };
}
