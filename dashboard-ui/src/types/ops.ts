// TypeScript shapes for the agent-brain OPS chat API.
// Mirrors agent_brain/services/ops_orchestrator.py response envelope.

export type OpsRiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;

export type OpsDecision = "ALLOW" | "REQUIRE_APPROVAL" | "BLOCK" | string;

export type OpsExecutionStatus =
  | "EXECUTED"
  | "SUCCESS"
  | "REJECTED"
  | "PENDING_APPROVAL"
  | "BLOCKED"
  | "INVALID_INPUT"
  | "TIMEOUT"
  | "RUNTIME_ERROR"
  | "SKIPPED"
  | string;

export interface OpsMcpTraceItem {
  server: string;
  tool: string;
  success: boolean;
  summary?: string | null;
  error?: string | null;
  result?: unknown;
}

export interface OpsMatchedRule {
  ruleId?: string;
  decision?: string;
  riskLevel?: string;
  description?: string;
  matched?: string;
}

export interface OpsSafetyValidation {
  decision?: OpsDecision;
  riskLevel?: OpsRiskLevel;
  matchedRules?: OpsMatchedRule[];
  reason?: string;
  safeAlternative?: string;
}

export interface OpsExecutionResult {
  status?: OpsExecutionStatus;
  command?: string;
  argv?: string[];
  executedAs?: string;
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
  startedAt?: string;
  endedAt?: string;
  durationMs?: number;
  timeoutSeconds?: number;
  reason?: string;
  commandId?: string;
}

export interface OpsAuditTrailItem {
  step: string;
  status: string;
  message: string;
  timestamp: string;
}

export interface OpsPlan {
  intentId?: string;
  intentLabel?: string;
  candidateCommands?: string[];
  mcpTools?: Array<{ server: string; tool: string; args?: Record<string, unknown> }>;
  extractedParams?: Record<string, unknown>;
}

// Output of agent_brain.safety.prompt_injection_guard.inspect()
export interface OpsInjectionMatchedPattern {
  ruleId: string;
  risk: string;
  description: string;
  sample: string;
}

export interface OpsPromptInjectionEnvelope {
  decision: OpsDecision;
  riskLevel: OpsRiskLevel;
  matchedPatterns: OpsInjectionMatchedPattern[];
  reason: string;
  reasonZh?: string;
}

// Output of agent_brain.safety.system_config_guard.evaluate()
export interface OpsConfigGuardMatchedPath {
  label: string;
  risk: string;
  matchedIn: "command" | "instruction" | string;
  snippet: string;
}

export interface OpsConfigGuardEnvelope {
  decision: OpsDecision;
  riskLevel: OpsRiskLevel;
  matchedPaths: OpsConfigGuardMatchedPath[];
  matchedVerb: string | null;
  reason: string;
  reasonZh?: string;
}

export interface OpsChatResponse {
  requestId: string;
  instruction: string;
  intent: string;
  intentLabel?: string;
  riskLevel?: OpsRiskLevel;
  decision?: OpsDecision;
  finalAnswer: string;
  plan?: OpsPlan;
  mcpTrace?: OpsMcpTraceItem[];
  promptInjection?: OpsPromptInjectionEnvelope;
  configGuard?: OpsConfigGuardEnvelope;
  safetyValidation?: OpsSafetyValidation;
  executionResult?: OpsExecutionResult | null;
  auditTrail?: OpsAuditTrailItem[];
  auditFile?: string | null;
}

export interface OpsAuditReplay {
  found: boolean;
  requestId?: string;
  events?: Array<Record<string, unknown>>;
  summary?: Record<string, unknown>;
}
