// Chinese localization for risk levels and severities.
//
// Covers both upper-case enums emitted by the FastAPI backend (LOW/MEDIUM/HIGH/CRITICAL)
// and the lower-case strings used in CoordinatorDecision.risk_level / strategy_impact.

export const RISK_ZH: Record<string, string> = {
  LOW: "低风险",
  MEDIUM: "中风险",
  HIGH: "高风险",
  CRITICAL: "紧急",
  low: "低风险",
  medium: "中风险",
  high: "高风险",
  critical: "紧急",
};

export function riskZh(level?: string | null): string {
  if (!level) return "—";
  return RISK_ZH[level] ?? String(level);
}

export const SEVERITY_ZH: Record<string, string> = {
  LOW: "低",
  MEDIUM: "中",
  HIGH: "高",
  CRITICAL: "严重",
};

export function severityZh(value?: string | null): string {
  if (!value) return "—";
  const up = String(value).toUpperCase();
  return SEVERITY_ZH[up] ?? String(value);
}
