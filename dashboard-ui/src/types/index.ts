export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface SecurityEvent {
  id: string;
  eventId: string;
  timestamp: string;
  sourceType: string;
  subject: string;
  action: string;
  object: string;
  severity: Severity;
  riskScore: number;
  labels: string[];
  context: Record<string, unknown>;
}

export interface DebateTurn {
  actor: "Planner" | "Red-Teamer" | "Planner-Revision" | "Coordinator";
  message: string;
  timestamp: string;
}

export interface Challenge {
  type: string;
  title: string;
  description: string;
  severity: Severity;
}

export interface DefenseAction {
  type: string;
  target: string;
  parameters: Record<string, unknown>;
}

export interface DefenseStrategy {
  strategyId: string;
  threatType: string;
  targetLayer: string;
  actions: DefenseAction[];
  ttl: number;
  confidence: number;
  rationale: string;
  approved: boolean;
}

export interface VerificationResult {
  passed: boolean;
  violatedConstraints: { code: string; description: string; severity: Severity; reason?: string }[];
  warnings: { code: string; description: string; severity: Severity; reason?: string }[];
  reason: string;
  suggestedFixes: string[];
}

export interface ExecutionRecord {
  executionId: string;
  strategyId: string;
  status: string;
  rollbackStatus: string;
  resultMessage: string;
  startTime: string;
  endTime: string;
  ttl?: number;
  generatedArtifacts?: Array<Record<string, unknown>>;
  failureReason?: string | null;
}

// MCP 工具调用 trace 条目（与后端 MCPToolCall 对齐）
// arguments 在某些 MCP 工具上可能不传；timestamp 是前端展示需要的可选字段，
// 后端如果没下发就保持 undefined，组件按存在性渐进展示。
export interface MCPToolCall {
  server: string;
  tool: string;
  arguments?: Record<string, unknown>;
  success: boolean;
  summary?: string;
  elapsedMs?: number | null;
  timestamp?: string;
}

// Red-Team 检测到的残余攻击路径
export interface ResidualAttackPath {
  source: string;
  target: string;
  nodes: string[];
  summary: string;
}

// Coordinator 聚合后的拓扑上下文摘要（来自 Planner.metadata + Red-Team.findings）
export interface TopologyContextSummary {
  topology_context_used: boolean;
  expected_blast_radius: "low" | "medium" | "high";
  affected_assets: string[];
  topology_evidence: string[];
  red_team: {
    topology_findings: string[];
    residual_attack_paths: ResidualAttackPath[];
    business_impact_risks: string[];
    recommended_constraints: string[];
  };
  mcp_errors: string[];
}

// 防御策略的回滚计划（用于 CoordinatorDecision.rollback_plan 字段）
export interface RollbackPlan {
  planId: string;
  steps: string[];
  triggerCondition: string;
}

// Phase 3: strategy lifecycle status emitted by the Coordinator
export type StrategyStatus =
  | "pending_validation"
  | "approved_for_execution"
  | "requires_approval"
  | "needs_revision"
  | "rejected";

// Phase 3: policy violation / warning / suggestion record returned by
// policy-mcp-server. Kept loose because the underlying server may evolve.
export interface PolicyRuleFinding {
  rule_id: string;
  rule_name: string;
  severity: string;
  action_index: number | null;
  action_type: string;
  target: string;
  message: string;
  remediation: string;
}

export interface PolicyRuleSuggestion {
  rule_id: string;
  title: string;
  detail: string;
  patch: Record<string, unknown>;
}

// Phase 3: PolicyValidation mirror of policy-mcp-server's data envelope
export interface PolicyValidation {
  valid: boolean;
  violations: PolicyRuleFinding[];
  warnings: PolicyRuleFinding[];
  requires_human_approval: boolean;
  suggestions: PolicyRuleSuggestion[];
  mcp_called: boolean;
  mcp_error: string | null;
}

// Phase 5: 单条 safety check 结果（人工确认边界判定）
export interface SafetyCheck {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

// ---------------------------------------------------------------------------
// Phase 6: 统一 MCP 数据模型（与 agent-brain Pydantic models 对齐）
// ---------------------------------------------------------------------------
// 这些接口对应后端 schemas.py 中的：
//   TopologyContext / StrategyImpact / ExecutionConstraint / FinalStrategy
// 设计原则：所有新字段都是可选（"?"），保持与历史 mock / 旧后端的兼容。
// ---------------------------------------------------------------------------

// 拓扑上下文的"扁平化"结构化视图（来自 Planner.metadata + Red-Team.findings）
// 与 TopologyContextSummary（嵌套 red_team）并存：FE 可任选其一消费。
export interface TopologyContext {
  topology_context_used: boolean;
  expected_blast_radius: string | null;
  affected_assets: string[];
  topology_evidence: string[];
  topology_findings: string[];
  residual_attack_paths: ResidualAttackPath[];
  business_impact_risks: string[];
  recommended_constraints: string[];
  mcp_errors: string[];
}

// 影响等级枚举（与后端 ImpactLevel 对齐）
export type ImpactLevel = "none" | "low" | "medium" | "high" | "critical";

// 策略影响 + 风险综合摘要
export interface StrategyImpact {
  impact_level: ImpactLevel;
  risk_level: "low" | "medium" | "high" | "critical";
  expected_blast_radius: string | null;
  affected_assets: string[];
  affected_paths: string[];
  residual_path_count: number;
  business_impact_count: number;
  rationale: string;
}

// 执行层硬约束（结构化版，与 final_strategy.execution_constraints 字符串数组并存）
export interface ExecutionConstraint {
  text: string;
  level: "info" | "warning" | "critical";
  source: "red_team" | "policy" | "topology" | "safety" | "coordinator" | string;
  rule_id?: string | null;
  detail?: string | null;
}

// final_strategy is the original DefenseStrategy enriched with the
// Coordinator-derived gating fields so the UI / Actuator MCP can decide
// rendering / execution without a join.
//
// Phase 6: 在保留全部历史字段的基础上，追加 spec 要求的 snake_case 字段。
// 全部以可选形式声明，旧后端 / 旧 mock 数据不会被破坏。
export interface FinalStrategy extends DefenseStrategy {
  status: StrategyStatus;
  human_approval_required: boolean;
  // Phase 5: human-approval boundary projection
  auto_execution_allowed: boolean;
  approval_reason: string[];
  execution_constraints: string[];
  safety_checks: SafetyCheck[];
  // ---- Phase 6: unified MCP data model snake_case mirror ----
  strategy_id?: string;
  action?: string | null;
  target?: string | null;
  ttl_minutes?: number | null;
  rollback_plan?: RollbackPlan | null;
  topology_context_summary?: TopologyContextSummary | Record<string, unknown>;
  mcp_trace?: MCPToolCall[];
  topology_context?: TopologyContext;
  strategy_impact?: StrategyImpact;
  execution_constraints_detailed?: ExecutionConstraint[];
}

// Coordinator 最终决策的完整聚合输出（agent-brain orchestrator 直接返回）
export interface CoordinatorDecision {
  final_strategy: FinalStrategy;
  decision_reasoning: string;
  risk_level: "low" | "medium" | "high" | "critical";
  confidence: number;
  topology_context_summary: TopologyContextSummary;
  mcp_trace: MCPToolCall[];
  rollback_plan: RollbackPlan | null;
  execution_constraints: string[];
  // Phase 3 additions
  status: StrategyStatus;
  human_approval_required: boolean;
  policy_validation: PolicyValidation;
  // Phase 5 additions: human-approval boundary
  auto_execution_allowed: boolean;
  approval_reason: string[];
  safety_checks: SafetyCheck[];
}

export interface ChainView {
  event: SecurityEvent;
  debate: {
    debateId: string;
    turns: DebateTurn[];
    unresolvedChallenges: Challenge[];
    nextAction: string;
    decisionReason: string;
  };
  strategy: DefenseStrategy;
  verification: VerificationResult;
  execution: ExecutionRecord;
  // 新增可选字段：未启用 MCP 时仍可省略，前端按存在性渐进展示
  coordinatorDecision?: CoordinatorDecision;
}

