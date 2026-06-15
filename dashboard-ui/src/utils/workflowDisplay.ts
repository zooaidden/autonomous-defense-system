import type { ChainView, CoordinatorDecision, DebateTurn, VerificationResult } from "../types";
import type {
  ActuatorWorkflowResponse,
  WorkflowHistoryTurn,
  WorkflowRunResult,
} from "../types/workflow";

/** Persisted workflow snapshot for refresh-safe replay on DebateProcessPage. */
export const WORKFLOW_LOCAL_STORAGE_KEY = "acd.workflow.latest";

export interface UnifiedWorkflowBundle {
  mode: "workflow" | "mock";
  historyTurns: DebateTurn[];
  unresolved: WorkflowRunResult["unresolvedChallenges"];
  coordinatorDecision: CoordinatorDecision | null;
  verification: VerificationResult | Record<string, unknown> | null;
  actuatorResponse: ActuatorWorkflowResponse | null;
  finalStrategy: Record<string, unknown> | null;
}

export function parsePersistedWorkflow(raw: string): WorkflowRunResult | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const r = parsed as Partial<WorkflowRunResult>;
    if (!r.debateState || !r.finalStrategy) return null;
    return parsed as WorkflowRunResult;
  } catch {
    return null;
  }
}

function formatTurnTimestamp(ts: unknown): string {
  if (ts == null) return "";
  if (typeof ts === "string") return ts;
  return String(ts);
}

/** Maps backend workflow debate history to DebateTurn[] used by the timeline UI. */
export function workflowHistoryToTurns(history: WorkflowHistoryTurn[] | undefined): DebateTurn[] {
  if (!history?.length) return [];
  return history.map((h) => ({
    actor: h.actor as DebateTurn["actor"],
    message: h.message,
    timestamp: formatTurnTimestamp(h.timestamp),
  }));
}

export function bundleFromWorkflow(workflow: WorkflowRunResult): UnifiedWorkflowBundle {
  const hist = workflow.debateState?.history ?? [];
  return {
    mode: "workflow",
    historyTurns: workflowHistoryToTurns(hist),
    unresolved:
      workflow.unresolvedChallenges?.length > 0
        ? workflow.unresolvedChallenges
        : workflow.debateState?.unresolvedChallenges ?? [],
    coordinatorDecision: workflow.coordinatorDecision ?? null,
    verification: workflow.verification ?? null,
    actuatorResponse: workflow.actuatorResponse ?? null,
    finalStrategy: workflow.finalStrategy ?? null,
  };
}

export function bundleFromChainView(chain: ChainView): UnifiedWorkflowBundle {
  const exec = chain.execution;
  const actuator: ActuatorWorkflowResponse | null = exec
    ? {
        status: exec.status,
        rollbackStatus: exec.rollbackStatus,
        executionId: exec.executionId,
        strategyId: exec.strategyId,
        resultMessage: exec.resultMessage,
        generatedArtifacts: exec.generatedArtifacts,
        failureReason: exec.failureReason ?? undefined,
      }
    : null;
  return {
    mode: "mock",
    historyTurns: chain.debate.turns,
    unresolved: chain.debate.unresolvedChallenges,
    coordinatorDecision: chain.coordinatorDecision ?? null,
    verification: chain.verification,
    actuatorResponse: actuator,
    finalStrategy: chain.strategy as unknown as Record<string, unknown>,
  };
}

/** Prefer snake_case trace from coordinator output; tolerate camelCase aliases and final_strategy mirror. */
export function pickMcpTrace(bundle: UnifiedWorkflowBundle): import("../types").MCPToolCall[] {
  const c = bundle.coordinatorDecision as
    | (CoordinatorDecision & { mcpTrace?: import("../types").MCPToolCall[] })
    | null;
  if (c) {
    const snake = c.mcp_trace;
    const camel = c.mcpTrace;
    const list = snake?.length ? snake : camel ?? [];
    if (list.length) return list;
  }
  const fs = bundle.finalStrategy as { mcp_trace?: import("../types").MCPToolCall[] } | null | undefined;
  return fs?.mcp_trace ?? [];
}
