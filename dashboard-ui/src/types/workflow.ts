import type { Challenge, CoordinatorDecision, VerificationResult } from "./index";
import type { OpsConfigGuardEnvelope, OpsPromptInjectionEnvelope } from "./ops";

/** Debate turn from agent-brain DebateState.history (JSON). */
export interface WorkflowHistoryTurn {
  round?: number;
  actor: string;
  message: string;
  timestamp?: string;
}

/** Minimal debate snapshot from POST /workflow/run debateState. */
export interface WorkflowDebateStateSnapshot {
  debateId?: string;
  history?: WorkflowHistoryTurn[];
  unresolvedChallenges?: Challenge[];
}

/**
 * Actuator outcome embedded in workflow response (actuator-service ExecutionRecord
 * unwrapped from ApiResponse, plus SIMULATED/SKIPPED shortcuts).
 */
export interface ActuatorWorkflowResponse {
  status?: string;
  executionId?: string;
  strategyId?: string;
  resultMessage?: string;
  startTime?: string;
  endTime?: string;
  ttl?: number;
  generatedArtifacts?: Array<Record<string, unknown>>;
  failureReason?: string | null;
  rollbackStatus?: string;
  strategySnapshot?: Record<string, unknown>;
  message?: string;
  code?: string | number;
  [key: string]: unknown;
}

/** Full envelope returned by agent-brain DebateOrchestrator.process_event */
export interface WorkflowRunResult {
  eventId: string;
  requestId?: string;
  processedAt: string;
  debateState: WorkflowDebateStateSnapshot & Record<string, unknown>;
  finalStrategy: Record<string, unknown>;
  unresolvedChallenges: Challenge[];
  nextAction: string;
  decisionReason: string;
  verification: VerificationResult | Record<string, unknown>;
  actuatorResponse: ActuatorWorkflowResponse;
  coordinatorDecision?: CoordinatorDecision;
  promptInjection?: OpsPromptInjectionEnvelope;
  configGuard?: OpsConfigGuardEnvelope;
  auditFile?: string | null;
}
