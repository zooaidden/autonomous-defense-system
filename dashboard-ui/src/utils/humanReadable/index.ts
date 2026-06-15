// Public barrel for the humanReadable subsystem. All page-level imports should
// come through this file so we can refactor the implementation freely.

export { describeVerificationHuman } from "./describeVerification";
export { describeActuatorHuman } from "./describeActuator";
export {
  describeCoordinatorDecisionHuman,
  describeFinalStrategyHuman,
} from "./describeStrategy";
export {
  describeMcpCallHuman,
  describeMcpArguments,
  toolLabelZh,
  type McpArgumentEntry,
} from "./describeMcp";
export { describeChallengeHuman } from "./describeChallenge";
export {
  describeArtifactHuman,
  type ArtifactDescriptor,
  type ArtifactRenderKind,
} from "./describeArtifact";
export {
  describeExecutionHuman,
  type ExecutionDescriptor,
} from "./describeExecution";
export {
  describeSecurityEventRow,
  dispositionChip,
  DISPOSITION_LABEL,
  DISPOSITION_TONE,
  type DispositionChip,
  type DispositionStatus,
  type EventRowDescriptor,
} from "./describeSecurityEvent";
export { computeWorkflowProgress } from "./computeProgress";

// Chinese dictionaries (re-exported for convenience; callers can also import
// directly from ./zh/* when they only need one mapping).
export { riskZh, severityZh, RISK_ZH, SEVERITY_ZH } from "./zh/risk";
export {
  decisionZh,
  strategyStatusZh,
  DECISION_ZH,
  STRATEGY_STATUS_ZH,
} from "./zh/decision";
export { intentZh, INTENT_ZH } from "./zh/intent";
export { threatZh, sourceTypeZh, THREAT_ZH, SOURCE_TYPE_ZH } from "./zh/threat";
export {
  actionZh,
  eventActionZh,
  ACTION_ZH,
  EVENT_ACTION_ZH,
} from "./zh/action";
export {
  statusZh,
  opsAuditStepZh,
  STATUS_ZH,
  OPS_AUDIT_STEP_ZH,
} from "./zh/status";
