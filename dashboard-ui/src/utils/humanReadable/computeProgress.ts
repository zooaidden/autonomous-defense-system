// Workflow / debate pipeline aggregate progress hint (0–100). Used by the
// DebateProgressRing visual; kept here so the value lives next to the other
// human-readable helpers.

import type { UnifiedWorkflowBundle } from "../workflowDisplay";

export function computeWorkflowProgress(bundle: UnifiedWorkflowBundle): number {
  let p = 10;
  const n = bundle.historyTurns.length;
  p += Math.min(38, Math.max(0, n - 1) * 9);
  if (bundle.coordinatorDecision) p += 22;
  const v = bundle.verification as { passed?: boolean } | null | undefined;
  if (v && typeof v.passed === "boolean") {
    p += v.passed ? 14 : 10;
  }
  const st = bundle.actuatorResponse?.status?.toUpperCase();
  if (st === "SUCCEEDED") return 100;
  if (st === "FAILED") p += 10;
  else if (st && st !== "SKIPPED") p += 8;
  return Math.min(96, Math.round(p));
}
