// Chinese localization for safety-gate decisions emitted by the ops orchestrator
// (ALLOW / REQUIRE_APPROVAL / BLOCK) and approval boundaries used by the
// CoordinatorDecision safety_checks.

export const DECISION_ZH: Record<string, string> = {
  ALLOW: "允许执行",
  REQUIRE_APPROVAL: "需人工审批",
  BLOCK: "已阻断",
};

export function decisionZh(decision?: string | null): string {
  if (!decision) return "—";
  return DECISION_ZH[decision] ?? String(decision);
}

// CoordinatorDecision.status uses lower_snake_case values; map them to readable
// Chinese phrases so the UI doesn't expose raw lifecycle keys.
export const STRATEGY_STATUS_ZH: Record<string, string> = {
  pending_validation: "待校验",
  approved_for_execution: "已批准执行",
  requires_approval: "需人工审批",
  needs_revision: "需修订",
  rejected: "已驳回",
};

export function strategyStatusZh(value?: string | null): string {
  if (!value) return "—";
  return STRATEGY_STATUS_ZH[value] ?? String(value);
}
