import type { OpsDecision, OpsRiskLevel } from "../../types/ops";

// Maps a security decision to a coloured pill.
// ALLOW = green, REQUIRE_APPROVAL = amber, BLOCK = red.

const DECISION_LABEL: Record<string, string> = {
  ALLOW: "允许执行",
  REQUIRE_APPROVAL: "等待审批",
  BLOCK: "已阻断",
};

const RISK_LABEL: Record<string, string> = {
  LOW: "低风险",
  MEDIUM: "中风险",
  HIGH: "高风险",
  CRITICAL: "极高风险",
};

function decisionTone(decision: string | undefined): "ok" | "warn" | "danger" | "muted" {
  if (!decision) return "muted";
  const d = decision.toUpperCase();
  if (d === "ALLOW") return "ok";
  if (d === "REQUIRE_APPROVAL" || d === "PENDING_APPROVAL") return "warn";
  if (d === "BLOCK" || d === "BLOCKED" || d === "REJECTED") return "danger";
  return "muted";
}

function riskTone(risk: string | undefined): "ok" | "warn" | "danger" | "muted" {
  if (!risk) return "muted";
  const r = risk.toUpperCase();
  if (r === "LOW") return "ok";
  if (r === "MEDIUM") return "warn";
  if (r === "HIGH" || r === "CRITICAL") return "danger";
  return "muted";
}

interface OpsDecisionBadgeProps {
  decision?: OpsDecision;
  size?: "sm" | "md" | "lg";
}

export function OpsDecisionBadge({ decision, size = "md" }: OpsDecisionBadgeProps) {
  const tone = decisionTone(decision);
  const text = decision ? DECISION_LABEL[decision.toUpperCase()] ?? decision : "未知决策";
  return (
    <span className={`ops-pill tone-${tone} size-${size}`}>
      <span className="ops-pill-dot" aria-hidden />
      {text}
    </span>
  );
}

interface OpsRiskBadgeProps {
  risk?: OpsRiskLevel;
  size?: "sm" | "md" | "lg";
}

export function OpsRiskBadge({ risk, size = "md" }: OpsRiskBadgeProps) {
  const tone = riskTone(risk);
  const text = risk ? RISK_LABEL[risk.toUpperCase()] ?? risk : "未知风险";
  return (
    <span className={`ops-pill tone-${tone} size-${size}`}>
      <span className="ops-pill-dot" aria-hidden />
      {text}
    </span>
  );
}

// Reusable plain colored chip - useful for execution-status etc.
interface OpsStatusChipProps {
  label: string;
  tone?: "ok" | "warn" | "danger" | "muted" | "info";
  icon?: string;
}

export function OpsStatusChip({ label, tone = "muted", icon }: OpsStatusChipProps) {
  return (
    <span className={`ops-pill tone-${tone} size-md`}>
      {icon ? <span className="ops-pill-icon">{icon}</span> : <span className="ops-pill-dot" aria-hidden />}
      {label}
    </span>
  );
}
