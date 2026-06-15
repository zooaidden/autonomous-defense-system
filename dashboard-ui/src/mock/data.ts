import type {
  ChainView,
  CoordinatorDecision,
  ExecutionRecord,
  MCPToolCall,
  SecurityEvent,
} from "../types";

const mockEvent: SecurityEvent = {
  id: "1",
  eventId: "evt-20260414-001",
  timestamp: "2026-04-14T15:48:00Z",
  sourceType: "EDR",
  subject: "pod/payment-service-9f8bd",
  action: "spawn_shell",
  object: "/bin/sh",
  severity: "HIGH",
  riskScore: 0.91,
  labels: ["t1059", "container-shell"],
  context: { namespace: "prod", cluster: "prod-cn-1", srcIp: "10.2.1.31" },
};

const mockExecution: ExecutionRecord = {
  executionId: "exe-001",
  strategyId: "stg-evt-20260414-001-p2",
  status: "SUCCEEDED",
  rollbackStatus: "AVAILABLE",
  resultMessage: "Simulated execution completed",
  startTime: "2026-04-14T15:49:10Z",
  endTime: "2026-04-14T15:49:12Z",
  ttl: 1800,
  generatedArtifacts: [
    {
      adapter: "K8sAdapter",
      format: "yaml",
      content:
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np-demo\nspec:\n  podSelector:\n    matchLabels:\n      app: payment-service\n",
    },
  ],
};

// Mock 三条典型 MCP 调用（覆盖 topology + policy 两个 server）
const mockMcpTrace: MCPToolCall[] = [
  {
    server: "topology-mcp-server",
    tool: "get_asset_info",
    arguments: { ip_or_asset_id: "10.2.1.31" },
    success: true,
    summary: "asset=payment-service-9f8bd, zone=internal, criticality=HIGH",
    elapsedMs: 32,
    timestamp: "2026-04-14T15:48:06Z",
  },
  {
    server: "topology-mcp-server",
    tool: "find_paths",
    arguments: { source: "10.2.1.31", target: "db-primary-01", max_depth: 4 },
    success: true,
    summary: "found 2 paths: [internal-payment -> internal-auth -> db-primary] / [internal-payment -> db-primary]",
    elapsedMs: 58,
    timestamp: "2026-04-14T15:48:08Z",
  },
  {
    server: "policy-mcp-server",
    tool: "validate_strategy",
    arguments: { strategyId: "stg-evt-20260414-001-p2" },
    success: true,
    summary: "validate_strategy: valid=true, violations=0, warnings=1, requires_human_approval=false",
    elapsedMs: 41,
    timestamp: "2026-04-14T15:48:28Z",
  },
];

const mockCoordinatorDecision: CoordinatorDecision = {
  final_strategy: {
    strategyId: "stg-evt-20260414-001-p2",
    threatType: "LATERAL_MOVEMENT",
    targetLayer: "WORKLOAD",
    ttl: 1800,
    confidence: 0.9,
    rationale: "spawn_shell high-risk detected; challenges covered by revision",
    approved: true,
    actions: [
      { type: "RESTRICT_EGRESS", target: "payment-service", parameters: { policy: "deny-untrusted-egress" } },
      { type: "ISOLATE_POD", target: "payment-service", parameters: { quarantineNamespace: "security-quarantine" } },
    ],
    status: "approved_for_execution",
    human_approval_required: false,
    auto_execution_allowed: true,
    approval_reason: [],
    execution_constraints: [],
    safety_checks: [
      { id: "critical_assets_impacted", label: "Critical assets impact", passed: true, detail: "No CRITICAL asset impact detected" },
      { id: "impact_level_high", label: "Impact level high", passed: true, detail: "blast_radius=medium, risk_level=medium" },
      { id: "destructive_action_type", label: "Destructive action type", passed: true, detail: "No firewall_deny_all / isolate_host / scale_down_critical_service detected" },
      { id: "rollback_plan_present", label: "Rollback plan present", passed: true, detail: "plan_id=rb-001, steps=2" },
      { id: "ttl_minutes_present", label: "TTL minutes present", passed: true, detail: "ttl=1800s (~30 min)" },
      { id: "policy_human_approval_not_required", label: "Policy MCP human-approval flag", passed: true, detail: "policy-mcp-server returned requires_human_approval=false" },
    ],
  },
  decision_reasoning:
    "reason=coverage_good_confidence_good; risk_level=medium | 主要挑战已覆盖且置信度达标，进入验证层。 | signals: high_risk=N, confidence_ok=Y, unresolved=0",
  risk_level: "medium",
  confidence: 0.9,
  topology_context_summary: {
    topology_context_used: true,
    expected_blast_radius: "medium",
    affected_assets: ["payment-service-9f8bd"],
    topology_evidence: ["srcIp 10.2.1.31 maps to payment-service-9f8bd (criticality=HIGH)"],
    red_team: {
      topology_findings: [],
      residual_attack_paths: [],
      business_impact_risks: [],
      recommended_constraints: [],
    },
    mcp_errors: [],
  },
  mcp_trace: mockMcpTrace,
  rollback_plan: { planId: "rb-001", steps: ["disable_egress_policy", "release_pod_isolation"], triggerCondition: "manual" },
  execution_constraints: [],
  status: "approved_for_execution",
  human_approval_required: false,
  policy_validation: {
    valid: true,
    violations: [],
    warnings: [],
    requires_human_approval: false,
    suggestions: [],
    mcp_called: true,
    mcp_error: null,
  },
  auto_execution_allowed: true,
  approval_reason: [],
  safety_checks: [
    { id: "critical_assets_impacted", label: "Critical assets impact", passed: true, detail: "No CRITICAL asset impact detected" },
    { id: "impact_level_high", label: "Impact level high", passed: true, detail: "blast_radius=medium, risk_level=medium" },
    { id: "destructive_action_type", label: "Destructive action type", passed: true, detail: "No firewall_deny_all / isolate_host / scale_down_critical_service detected" },
    { id: "rollback_plan_present", label: "Rollback plan present", passed: true, detail: "plan_id=rb-001, steps=2" },
    { id: "ttl_minutes_present", label: "TTL minutes present", passed: true, detail: "ttl=1800s (~30 min)" },
    { id: "policy_human_approval_not_required", label: "Policy MCP human-approval flag", passed: true, detail: "policy-mcp-server returned requires_human_approval=false" },
  ],
};

export const mockChainView: ChainView = {
  event: mockEvent,
  debate: {
    debateId: "deb-001",
    turns: [
      { actor: "Planner", message: "Generated P1 with restrict_egress + isolate_pod", timestamp: "2026-04-14T15:48:05Z" },
      { actor: "Red-Teamer", message: "Raised encoding bypass and scope-risk challenges", timestamp: "2026-04-14T15:48:12Z" },
      { actor: "Planner-Revision", message: "Added anomaly scoring and reduced blast radius", timestamp: "2026-04-14T15:48:20Z" },
      { actor: "Coordinator", message: "Coverage is sufficient; enter verification", timestamp: "2026-04-14T15:48:30Z" },
    ],
    unresolvedChallenges: [],
    nextAction: "ENTER_VERIFICATION",
    decisionReason: "coverage_good_confidence_good",
  },
  strategy: {
    strategyId: "stg-evt-20260414-001-p2",
    threatType: "LATERAL_MOVEMENT",
    targetLayer: "WORKLOAD",
    ttl: 1800,
    confidence: 0.9,
    rationale: "spawn_shell high-risk detected; challenges covered by revision",
    approved: true,
    actions: [
      { type: "RESTRICT_EGRESS", target: "payment-service", parameters: { policy: "deny-untrusted-egress" } },
      { type: "ISOLATE_POD", target: "payment-service", parameters: { quarantineNamespace: "security-quarantine" } },
    ],
  },
  verification: {
    passed: true,
    violatedConstraints: [],
    warnings: [],
    reason: "PASSED",
    suggestedFixes: [],
  },
  execution: mockExecution,
  coordinatorDecision: mockCoordinatorDecision,
};

// ---------------------------------------------------------------------------
// 高风险示例：需要人工审批（用于 dashboard 展示 SafetyChecksPanel 的 fail 状态）
// ---------------------------------------------------------------------------
export const mockHumanApprovalDecision: CoordinatorDecision = {
  final_strategy: {
    strategyId: "stg-evt-20260414-002-p1",
    threatType: "DATA_EXFILTRATION",
    targetLayer: "DATA",
    ttl: 3600,
    confidence: 0.85,
    rationale: "log4shell exploit detected against db-primary; high-impact response required",
    approved: false,
    actions: [
      { type: "ISOLATE_HOST", target: "db-primary-01", parameters: { reason: "log4shell" } },
    ],
    status: "requires_approval",
    human_approval_required: true,
    auto_execution_allowed: false,
    approval_reason: [
      "Critical asset impacted: db-primary-01",
      "Destructive action type: ISOLATE_HOST",
      "Policy MCP returned requires_human_approval=true",
    ],
    execution_constraints: [
      "Auto-execution blocked: human approval required",
      "Manual rollback within 30 minutes if anomaly detected",
    ],
    safety_checks: [
      { id: "critical_assets_impacted", label: "Critical assets impact", passed: false, detail: "db-primary-01 (criticality=CRITICAL) is in scope" },
      { id: "impact_level_high", label: "Impact level high", passed: false, detail: "blast_radius=high" },
      { id: "destructive_action_type", label: "Destructive action type", passed: false, detail: "ISOLATE_HOST is destructive" },
      { id: "rollback_plan_present", label: "Rollback plan present", passed: true, detail: "plan_id=rb-002, steps=3" },
      { id: "ttl_minutes_present", label: "TTL minutes present", passed: true, detail: "ttl=3600s (~60 min)" },
      { id: "policy_human_approval_not_required", label: "Policy MCP human-approval flag", passed: false, detail: "policy-mcp-server returned requires_human_approval=true" },
    ],
    strategy_id: "stg-evt-20260414-002-p1",
    action: "ISOLATE_HOST",
    target: "db-primary-01",
    ttl_minutes: 60,
    rollback_plan: { planId: "rb-002", steps: ["release_isolation", "verify_health", "open_egress"], triggerCondition: "manual" },
    topology_context_summary: {},
    mcp_trace: mockMcpTrace,
    strategy_impact: {
      impact_level: "high",
      risk_level: "high",
      expected_blast_radius: "high",
      affected_assets: ["db-primary-01"],
      affected_paths: [],
      residual_path_count: 0,
      business_impact_count: 1,
      rationale: "impact=high; risk=high; residual_paths=0",
    },
  },
  decision_reasoning: "reason=critical_asset_destructive_action; policy_required=Y; human_required=Y",
  risk_level: "high",
  confidence: 0.85,
  topology_context_summary: {
    topology_context_used: true,
    expected_blast_radius: "high",
    affected_assets: ["db-primary-01"],
    topology_evidence: ["db-primary-01 is criticality=CRITICAL in zone=database"],
    red_team: {
      topology_findings: ["isolating db-primary-01 will disrupt 3 production payment paths"],
      residual_attack_paths: [],
      business_impact_risks: ["payment service downtime"],
      recommended_constraints: ["Require human approval before isolation"],
    },
    mcp_errors: [],
  },
  mcp_trace: mockMcpTrace,
  rollback_plan: { planId: "rb-002", steps: ["release_isolation", "verify_health", "open_egress"], triggerCondition: "manual" },
  execution_constraints: [
    "Auto-execution blocked: human approval required",
    "Manual rollback within 30 minutes if anomaly detected",
  ],
  status: "requires_approval",
  human_approval_required: true,
  policy_validation: {
    valid: true,
    violations: [],
    warnings: [],
    requires_human_approval: true,
    suggestions: [],
    mcp_called: true,
    mcp_error: null,
  },
  auto_execution_allowed: false,
  approval_reason: [
    "Critical asset impacted: db-primary-01",
    "Destructive action type: ISOLATE_HOST",
    "Policy MCP returned requires_human_approval=true",
  ],
  safety_checks: [
    { id: "critical_assets_impacted", label: "Critical assets impact", passed: false, detail: "db-primary-01 (criticality=CRITICAL) is in scope" },
    { id: "impact_level_high", label: "Impact level high", passed: false, detail: "blast_radius=high" },
    { id: "destructive_action_type", label: "Destructive action type", passed: false, detail: "ISOLATE_HOST is destructive" },
    { id: "rollback_plan_present", label: "Rollback plan present", passed: true, detail: "plan_id=rb-002, steps=3" },
    { id: "ttl_minutes_present", label: "TTL minutes present", passed: true, detail: "ttl=3600s (~60 min)" },
    { id: "policy_human_approval_not_required", label: "Policy MCP human-approval flag", passed: false, detail: "policy-mcp-server returned requires_human_approval=true" },
  ],
};

export const mockEvents: SecurityEvent[] = [
  mockEvent,
  {
    ...mockEvent,
    id: "2",
    eventId: "evt-20260414-002",
    action: "http_request",
    object: "/api/search",
    severity: "CRITICAL",
    riskScore: 0.97,
    labels: ["log4shell", "t1190"],
    timestamp: "2026-04-14T13:08:00Z",
  },
  {
    ...mockEvent,
    id: "3",
    eventId: "evt-20260414-003",
    severity: "MEDIUM",
    riskScore: 0.55,
    action: "anomalous_connection",
    object: "db-primary",
    timestamp: "2026-04-14T10:18:00Z",
  },
  // 多补几条用于趋势图：跨多天 + 不同风险
  {
    ...mockEvent,
    id: "4",
    eventId: "evt-20260413-004",
    severity: "HIGH",
    riskScore: 0.83,
    action: "credential_dump",
    object: "/etc/shadow",
    timestamp: "2026-04-13T11:42:00Z",
  },
  {
    ...mockEvent,
    id: "5",
    eventId: "evt-20260412-005",
    severity: "LOW",
    riskScore: 0.31,
    action: "port_scan",
    object: "10.2.1.0/24",
    timestamp: "2026-04-12T09:05:00Z",
  },
  {
    ...mockEvent,
    id: "6",
    eventId: "evt-20260411-006",
    severity: "MEDIUM",
    riskScore: 0.62,
    action: "http_request",
    object: "/api/admin",
    timestamp: "2026-04-11T16:21:00Z",
  },
];

export const mockExecutions: ExecutionRecord[] = [
  mockExecution,
  { ...mockExecution, executionId: "exe-002", strategyId: "stg-evt-20260414-002-p2", rollbackStatus: "SUCCEEDED" },
];

