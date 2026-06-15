from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DebateStatus(str, Enum):
    INIT = "INIT"
    IN_PROGRESS = "IN_PROGRESS"
    NEEDS_REVISION = "NEEDS_REVISION"
    READY_FOR_DECISION = "READY_FOR_DECISION"
    CLOSED = "CLOSED"


class DecisionType(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"
    NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"


class NextAction(str, Enum):
    CONTINUE_DEBATE = "CONTINUE_DEBATE"
    ENTER_VERIFICATION = "ENTER_VERIFICATION"
    REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"
    STOP = "STOP"


class ThreatType(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    BRUTE_FORCE = "BRUTE_FORCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DDOS = "DDOS"
    UNKNOWN = "UNKNOWN"


class TargetLayer(str, Enum):
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"
    IDENTITY = "IDENTITY"
    WORKLOAD = "WORKLOAD"
    KUBERNETES = "KUBERNETES"
    APPLICATION = "APPLICATION"
    DATA = "DATA"


class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    RESTRICT_EGRESS = "RESTRICT_EGRESS"
    ISOLATE_POD = "ISOLATE_POD"
    ALERT_ONLY = "ALERT_ONLY"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    ISOLATE_HOST = "ISOLATE_HOST"
    REVOKE_TOKEN = "REVOKE_TOKEN"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    APPLY_WAF_RULE = "APPLY_WAF_RULE"
    APPLY_FIREWALL_RULE = "APPLY_FIREWALL_RULE"
    SCALE_PROTECTION = "SCALE_PROTECTION"


class GeneratedBy(str, Enum):
    PLANNER = "PLANNER"
    COORDINATOR = "COORDINATOR"
    HUMAN_ANALYST = "HUMAN_ANALYST"
    HYBRID = "HYBRID"


class SecurityEvent(BaseModel):
    eventId: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sourceType: str
    subject: str
    action: str
    object: str
    context: dict[str, Any] = Field(default_factory=dict)
    severity: Severity
    riskScore: float = Field(ge=0, le=1)
    labels: list[str] = Field(default_factory=list)


class DefenseAction(BaseModel):
    type: ActionType
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class StrategyScope(BaseModel):
    assets: list[str] = Field(default_factory=list)
    namespaces: list[str] = Field(default_factory=list)
    tenantId: str | None = None


class RollbackPlan(BaseModel):
    planId: str
    steps: list[str] = Field(default_factory=list)
    triggerCondition: str


class DefenseStrategy(BaseModel):
    strategyId: str
    threatType: ThreatType
    targetLayer: TargetLayer
    actions: list[DefenseAction] = Field(default_factory=list)
    scope: StrategyScope
    ttl: int = Field(gt=0)
    rollbackPlan: RollbackPlan
    confidence: float = Field(ge=0, le=1)
    rationale: str
    generatedBy: GeneratedBy
    approved: bool = False


class RiskLevel(str, Enum):
    """Coordinator 综合评估出的最终风险等级，与 BlastRadius 不同：
    BlastRadius 仅来自 Planner 的拓扑预估，RiskLevel 还会聚合 Red-Team
    findings、未解决挑战数、事件 severity 等多维信号。
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MCPToolCall(BaseModel):
    """记录单次 MCP 工具调用的 trace 条目，便于审计和可视化。

    字段约定与 dashboard-ui 端展示组件保持一致：
      - server: MCP server 名称，例如 "topology-mcp-server"
      - tool: 工具名，例如 "get_asset_info"
      - arguments: 调用参数（已脱敏 / JSON 可序列化）
      - success: 调用是否成功
      - summary: 一句话摘要，便于前端列表直接显示（None 表示无摘要）
      - elapsedMs: 调用耗时毫秒，None 表示未测量
      - timestamp: 调用发生时间 ISO 字符串，None 表示未记录
    """

    server: str = "topology-mcp-server"
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    success: bool
    # Phase 6 unified contract: 同时允许 None / "" / 文字摘要
    summary: str | None = ""
    elapsedMs: int | None = None
    # Phase 6 unified contract: 显式时间戳字段，便于前端按时间线渲染
    timestamp: str | None = None


class StrategyStatus(str, Enum):
    """Coordinator 给最终策略打的执行状态标签。

    - PENDING_VALIDATION: 还没有过 policy 校验
    - APPROVED_FOR_EXECUTION: policy 校验通过，可下发执行
    - REQUIRES_APPROVAL: 需要人工审批后才能执行（高风险但仍可治理）
    - NEEDS_REVISION: 命中关键违规，必须先修订策略再走流程
    - REJECTED: 被 Coordinator 直接否决（例如上游没有任何策略）
    """

    PENDING_VALIDATION = "pending_validation"
    APPROVED_FOR_EXECUTION = "approved_for_execution"
    REQUIRES_APPROVAL = "requires_approval"
    NEEDS_REVISION = "needs_revision"
    REJECTED = "rejected"


class PolicyValidation(BaseModel):
    """policy-mcp-server 校验结果在 FinalDecision 上的镜像。

    与 policy-mcp-server 返回的 ``data`` 形状对齐，但用 Pydantic 约束让
    上游 / 前端拿到稳定的字段名。``mcp_called`` 用来标记本次决策是否
    真实跑过 policy MCP（disabled / 失败时为 False，方便前端区分）。
    """

    valid: bool = True
    violations: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[dict[str, Any]] = Field(default_factory=list)
    requires_human_approval: bool = False
    suggestions: list[dict[str, Any]] = Field(default_factory=list)
    mcp_called: bool = False
    mcp_error: str | None = None


class SafetyCheck(BaseModel):
    """单条人工确认边界的安全检查结果。

    每条 safety_check 都对应"是否允许自动执行"判定中的一项独立信号。
    任何一项 ``passed=False`` 都会强制 Coordinator 把策略置为
    ``human_approval_required=true`` / ``auto_execution_allowed=false``。

    字段说明：
      - id:     稳定标识，前端按 id 渲染图标 / 中英文文案
      - label:  人类可读的简短标题
      - passed: 是否通过（False 即触发人工审批边界）
      - detail: 触发原因或通过依据，供前端显示在 tooltip / 详情卡
    """

    id: str
    label: str
    passed: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# Phase 6: 统一 MCP 数据模型
# ---------------------------------------------------------------------------
#
# 以下四个模型把"原本散落在 dict / 字符串数组里的字段"升级为结构化对象，
# 便于前后端契约稳定。所有模型都满足以下原则：
#   1. 不替代任何现有字段 —— 新模型仅作为补充投影，旧的 camelCase 字段保留；
#   2. 全部字段带默认值 —— 老调用方反序列化时不会因缺字段失败；
#   3. snake_case 命名 —— 与 dashboard-ui / Coordinator orchestrator 输出一致。
# ---------------------------------------------------------------------------


class TopologyContext(BaseModel):
    """Coordinator 聚合后的拓扑上下文（Planner.metadata + Red-Team.findings 视图）。

    与 ``FinalDecision.topologyContextSummary`` 是同一份信息的结构化版本。
    前端如果需要严格类型，可以直接消费 ``topologyContext``；旧的
    ``topologyContextSummary: dict`` 仍然保留以兼容旧 API 客户端。

    ``expected_blast_radius`` 用 ``str`` 而非 BlastRadius enum 是为了避免
    与后定义的枚举之间的前向引用，取值约定与 BlastRadius 一致：
    ``"low" | "medium" | "high"``，未评估时为 None。

    ``residual_attack_paths`` 用 ``list[dict]`` 而非 ResidualAttackPath，
    同样为了规避前向引用；每个 dict 的形状为：
    ``{"source": str, "target": str, "nodes": list[str], "summary": str}``。
    """

    topology_context_used: bool = False
    expected_blast_radius: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    topology_evidence: list[str] = Field(default_factory=list)
    # Red-Team 拓扑视角的派生信号
    topology_findings: list[str] = Field(default_factory=list)
    residual_attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    business_impact_risks: list[str] = Field(default_factory=list)
    recommended_constraints: list[str] = Field(default_factory=list)
    # 任意一侧 MCP 调用失败时的错误聚合（与 topologyContextSummary["mcp_errors"] 对齐）
    mcp_errors: list[str] = Field(default_factory=list)


class ImpactLevel(str, Enum):
    """策略对网络的预估影响等级（与 BlastRadius 同形但语义更宽：可表示 N/A）。

    - NONE:     未评估（默认）
    - LOW/MEDIUM/HIGH/CRITICAL: 与 BlastRadius / RiskLevel 的映射保持一致
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrategyImpact(BaseModel):
    """对一条策略的"影响面 + 风险综合"摘要。

    由 Coordinator 在最终决策时根据 Planner / Red-Team / Policy MCP 的多维信号
    派生出来，前端在审批卡 / 决策推理面板上直接渲染。

    ``expected_blast_radius`` 同 TopologyContext，用 ``str`` 避开前向引用：
    ``"low" | "medium" | "high"``，未评估时为 None。
    """

    impact_level: ImpactLevel = ImpactLevel.NONE
    risk_level: RiskLevel = RiskLevel.LOW
    expected_blast_radius: str | None = None
    # 受影响资产（来自 Planner.affected_assets ∪ scope.assets，去重保序）
    affected_assets: list[str] = Field(default_factory=list)
    # 受影响 / 残余 / 业务路径数量等可量化信号
    affected_paths: list[str] = Field(default_factory=list)
    residual_path_count: int = 0
    business_impact_count: int = 0
    # 自由文本的综合解释，方便前端在 hover 时显示一段说明
    rationale: str = ""


class ExecutionConstraint(BaseModel):
    """执行层硬约束的结构化形式。

    Coordinator 当前仍输出 ``executionConstraints: list[str]``（向后兼容），
    本模型只是把单条字符串 + 元信息升级为结构化对象，便于前端：
      1. 按 ``level`` 高亮显示（critical 红 / warning 黄 / info 灰）
      2. 按 ``source`` 区分约束来源（red_team / policy / topology / safety）
      3. 按 ``rule_id`` 跳转到具体策略规则
    所有字段都带默认值；最少只填 ``text`` 也可创建一条约束。
    """

    text: str = ""
    level: str = "info"  # info | warning | critical
    source: str = "coordinator"  # red_team | policy | topology | safety | coordinator
    rule_id: str | None = None
    detail: str | None = None


class FinalStrategy(BaseModel):
    """最终策略的统一前后端契约（Phase 6）。

    设计目标：Coordinator → orchestrator → dashboard-ui 这条链路上"前端读到的
    最终策略对象"对应这一份模型。同时为了不破坏既有 API：
      - 暴露 spec 要求的 13 个 snake_case 字段（必填或带默认值）；
      - 同时保留旧 DefenseStrategy 的 camelCase 字段（threatType / actions / ttl
        / confidence / rationale / approved 等），让现有前端 / 测试不破。

    spec 字段 (snake_case)：
      strategy_id / action / target / scope / ttl_minutes / rollback_plan /
      human_approval_required / auto_execution_allowed / approval_reason /
      execution_constraints / safety_checks / topology_context_summary /
      mcp_trace
    """

    # ---- spec required fields (Phase 6) ----
    strategy_id: str
    # 主导动作类型（取 actions[0].type，单数）；多动作策略可在 ``actions`` 全量列出
    action: str | None = None
    target: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    # 分钟级 TTL：方便前端展示；秒级 TTL 通过下方 ``ttl`` 兼容字段保留
    ttl_minutes: int | None = None
    rollback_plan: dict[str, Any] | None = None
    human_approval_required: bool = False
    auto_execution_allowed: bool = True
    approval_reason: list[str] = Field(default_factory=list)
    execution_constraints: list[str] = Field(default_factory=list)
    safety_checks: list[SafetyCheck] = Field(default_factory=list)
    topology_context_summary: dict[str, Any] = Field(default_factory=dict)
    mcp_trace: list[MCPToolCall] = Field(default_factory=list)

    # ---- 兼容旧 DefenseStrategy 字段（保留 camelCase，避免破坏既有前端） ----
    strategyId: str | None = None
    threatType: str | None = None
    targetLayer: str | None = None
    actions: list[dict[str, Any]] = Field(default_factory=list)
    ttl: int | None = None  # 秒级 TTL（与 DefenseStrategy.ttl 一致）
    confidence: float | None = None
    rationale: str | None = None
    approved: bool = False
    generatedBy: str | None = None
    rollbackPlan: dict[str, Any] | None = None  # camelCase 别名

    # ---- Phase 5 已存在字段（保留） ----
    status: StrategyStatus = StrategyStatus.PENDING_VALIDATION

    # ---- Phase 6 派生 ----
    risk_level: RiskLevel = RiskLevel.LOW
    topology_context: TopologyContext | None = None
    strategy_impact: StrategyImpact | None = None
    execution_constraints_detailed: list[ExecutionConstraint] = Field(default_factory=list)


class FinalDecision(BaseModel):
    decision: DecisionType
    owner: str
    rationale: str
    nextAction: NextAction
    unresolvedChallenges: list["Challenge"] = Field(default_factory=list)
    decisionReason: str
    decidedAt: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # ---- 拓扑/MCP 整合相关的扩展字段（向后兼容：默认值确保旧反序列化不破坏） ----
    riskLevel: RiskLevel = RiskLevel.LOW
    decisionReasoning: str = ""
    topologyContextSummary: dict[str, Any] = Field(default_factory=dict)
    mcpTrace: list[MCPToolCall] = Field(default_factory=list)
    executionConstraints: list[str] = Field(default_factory=list)
    # ---- 第三阶段新增：policy-mcp-server 集成 ----
    status: StrategyStatus = StrategyStatus.PENDING_VALIDATION
    humanApprovalRequired: bool = False
    policyValidation: PolicyValidation = Field(default_factory=PolicyValidation)
    # ---- 第五阶段新增：人工确认边界 ----
    # autoExecutionAllowed 是 humanApprovalRequired 的反向投影，但显式存储
    # 一份让执行链 / Actuator MCP 可以直接读，避免分散判定。
    autoExecutionAllowed: bool = True
    # approvalReason 仅在 humanApprovalRequired=True 时非空，按发生顺序记录
    # 触发原因（用于 Dashboard 在审批卡片上罗列原因）。
    approvalReason: list[str] = Field(default_factory=list)
    # safetyChecks 是 6 条独立判定的结构化结果，前端可直接渲染清单。
    safetyChecks: list[SafetyCheck] = Field(default_factory=list)


class DebateTurn(BaseModel):
    round: int = Field(ge=1)
    actor: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Challenge(BaseModel):
    type: str
    title: str
    description: str
    severity: Severity


class BlastRadius(str, Enum):
    """期望影响面等级：用于 Planner 在生成策略时表达对拓扑破坏面的预估。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PlannerTopologyMetadata(BaseModel):
    """Planner 在生成策略时附带的拓扑上下文 metadata。

    所有字段都有合理默认值，未启用 MCP 时整体保持空状态，不影响下游消费者。
    """

    topology_context_used: bool = False
    affected_assets: list[str] = Field(default_factory=list)
    expected_blast_radius: BlastRadius = BlastRadius.LOW
    topology_evidence: list[str] = Field(default_factory=list)
    mcp_tool_calls: list[MCPToolCall] = Field(default_factory=list)
    mcp_error: str | None = None


class ResidualAttackPath(BaseModel):
    """Red-Team 检测到的"策略未覆盖的攻击路径"。

    用法：当 Planner 策略仅阻断 source/target 链路上的部分节点，
    而 ``find_paths`` 仍能在剩余拓扑里找到完整的 ``source -> target``
    通路时，对应路径会被记录为 ResidualAttackPath。
    """

    source: str
    target: str
    nodes: list[str] = Field(default_factory=list)
    summary: str = ""


class RedTeamFindings(BaseModel):
    """Red-Team 在挑战策略阶段附带的拓扑分析 findings。

    与 ``PlannerTopologyMetadata`` 类似：所有字段默认空，MCP 关闭或失败时
    整体保持空状态，不破坏下游 Coordinator/Revision 的正常流程。
    """

    topology_based_findings: list[str] = Field(default_factory=list)
    residual_attack_paths: list[ResidualAttackPath] = Field(default_factory=list)
    business_impact_risks: list[str] = Field(default_factory=list)
    recommended_constraints: list[str] = Field(default_factory=list)
    mcp_tool_calls: list[MCPToolCall] = Field(default_factory=list)
    mcp_error: str | None = None


class DebateState(BaseModel):
    debateId: str
    securityEvent: SecurityEvent
    retrievedContext: list[str] = Field(default_factory=list)
    plannerProposal: DefenseStrategy | None = None
    plannerMetadata: PlannerTopologyMetadata | None = None
    redTeamChallenges: list[Challenge] = Field(default_factory=list)
    redTeamFindings: RedTeamFindings | None = None
    unresolvedChallenges: list[Challenge] = Field(default_factory=list)
    revisedProposal: DefenseStrategy | None = None
    round: int = Field(ge=0, default=0)
    maxRounds: int = 2
    confidenceThreshold: float = Field(default=0.85, ge=0, le=1)
    highRiskThreshold: float = Field(default=0.9, ge=0, le=1)
    status: DebateStatus = DebateStatus.INIT
    finalDecision: FinalDecision | None = None
    history: list[DebateTurn] = Field(default_factory=list)
    audit_turns: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Per-agent reasoning snapshots for full audit trace",
    )


class VerificationResult(BaseModel):
    passed: bool
    violatedConstraints: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    reason: str
    suggestedFixes: list[str] = Field(default_factory=list)

