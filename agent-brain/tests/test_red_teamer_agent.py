from pathlib import Path

from agent_brain.agents import RedTeamerAgent
from agent_brain.integrations.mcp_client import TopologyMCPClient
from agent_brain.models import (
    ActionType,
    DebateState,
    DefenseAction,
    DefenseStrategy,
    GeneratedBy,
    RollbackPlan,
    SecurityEvent,
    Severity,
    StrategyScope,
    TargetLayer,
    ThreatType,
)
from agent_brain.services import MockLLMClient


# 拓扑 mock server 路径，供启用 MCP 时的 local 模式使用
_TOPOLOGY_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "topology-mcp-server"
)


def _base_event(context: dict | None = None) -> SecurityEvent:
    return SecurityEvent(
        eventId="evt-rt-001",
        sourceType="WAF",
        subject="public-gateway",
        action="http_request",
        object="/api/search",
        context=context or {"payload": "test"},
        severity=Severity.HIGH,
        riskScore=0.82,
        labels=["test"],
    )


def _state_with_strategy(
    actions: list[DefenseAction],
    *,
    event_context: dict | None = None,
    rollback_steps: list[str] | None = None,
    rollback_trigger: str = "manual",
    ttl: int = 1200,
    scope_assets: list[str] | None = None,
) -> DebateState:
    strategy = DefenseStrategy(
        strategyId="stg-test",
        threatType=ThreatType.UNKNOWN,
        targetLayer=TargetLayer.APPLICATION,
        actions=actions,
        scope=StrategyScope(
            assets=scope_assets or ["public-gateway"],
            namespaces=["edge"],
            tenantId="tenant-a",
        ),
        ttl=ttl,
        rollbackPlan=RollbackPlan(
            planId="rb-test",
            steps=rollback_steps if rollback_steps is not None else ["rollback"],
            triggerCondition=rollback_trigger,
        ),
        confidence=0.8,
        rationale="test strategy",
        generatedBy=GeneratedBy.PLANNER,
        approved=False,
    )
    return DebateState(
        debateId="deb-rt-001",
        securityEvent=_base_event(event_context),
        plannerProposal=strategy,
    )


def _make_mcp_red_teamer() -> RedTeamerAgent:
    client = TopologyMCPClient(
        enabled=True, mode="local", server_path=_TOPOLOGY_FIXTURE_PATH
    )
    return RedTeamerAgent(MockLLMClient(), topology_client=client)


# ---------------------------------------------------------------------------
# 旧回归测试：MCP 默认关闭时，行为完全保持
# ---------------------------------------------------------------------------


def test_red_teamer_prioritizes_distributed_bypass_for_block_ip_only():
    state = _state_with_strategy(
        [DefenseAction(type=ActionType.BLOCK_IP, target="203.0.113.9", parameters={})]
    )
    output = RedTeamerAgent(MockLLMClient()).run(state)
    titles = [c.title for c in output.redTeamChallenges]
    assert "Multi-source distributed bypass" in titles
    assert output.redTeamChallenges[0].severity.value in {"HIGH", "MEDIUM", "LOW", "CRITICAL"}
    # MCP 默认关闭：findings 是空对象 + disabled 提示
    assert output.redTeamFindings is not None
    assert output.redTeamFindings.topology_based_findings == []
    assert output.redTeamFindings.mcp_tool_calls == []


def test_red_teamer_prioritizes_encoding_and_mutation_for_waf_only():
    state = _state_with_strategy(
        [
            DefenseAction(
                type=ActionType.APPLY_WAF_RULE,
                target="/api/search",
                parameters={"ruleType": "regex", "pattern": "jndi:ldap"},
            )
        ]
    )
    output = RedTeamerAgent(MockLLMClient()).run(state)
    titles = [c.title for c in output.redTeamChallenges]
    assert "Base64 encoding bypass" in titles
    assert "Application-layer mutation bypass" in titles
    assert output.redTeamChallenges


# ---------------------------------------------------------------------------
# 拓扑层挑战：启用 MCP 后，evaluate_strategy_impact + 衍生发现
# ---------------------------------------------------------------------------


def test_red_teamer_flags_critical_asset_isolation_with_mcp():
    """ISOLATE_POD app-payment-01 (CRITICAL) 时应触发拓扑层 findings 与建议。"""
    state = _state_with_strategy(
        actions=[
            DefenseAction(
                type=ActionType.ISOLATE_POD,
                target="app-payment-01",
                parameters={},
            )
        ],
        scope_assets=["app-payment-01"],
    )
    output = _make_mcp_red_teamer().run(state)
    findings = output.redTeamFindings
    assert findings is not None
    # MCP 至少调用了 evaluate_strategy_impact 与 get_neighbors
    tool_names = {c.tool for c in findings.mcp_tool_calls}
    assert "evaluate_strategy_impact" in tool_names
    assert "get_neighbors" in tool_names
    assert all(c.server == "topology-mcp-server" for c in findings.mcp_tool_calls)
    # CRITICAL 资产挑战应该出现
    joined = " | ".join(findings.topology_based_findings).lower()
    assert "critical" in joined
    # 业务影响风险应至少有一条
    assert findings.business_impact_risks
    # 推荐约束至少包含"用 RESTRICT_EGRESS 替代 ISOLATE/BLOCK"
    assert any(
        "RESTRICT_EGRESS" in r or "restrict_egress" in r.lower()
        for r in findings.recommended_constraints
    )
    # 这些拓扑发现也以 Challenge 形式写到了 redTeamChallenges
    challenge_types = {c.type for c in output.redTeamChallenges}
    assert "business_impact" in challenge_types or "topology" in challenge_types
    assert "constraint" in challenge_types


def test_red_teamer_detects_residual_attack_path():
    """事件含 src/dst，策略只阻断单点时，find_paths 仍能找到残余路径。"""
    # event 提供 src=10.10.1.10 (dmz-web-01), dst=10.30.1.10 (db-primary-01)
    # 策略只 ISOLATE 一个不在路径上的资产 -> 应得到残余攻击路径
    state = _state_with_strategy(
        actions=[
            DefenseAction(
                type=ActionType.ISOLATE_POD,
                target="mgmt-bastion-01",  # 不在 dmz-web-01 -> db-primary-01 主路径上
                parameters={},
            )
        ],
        event_context={"srcIp": "10.10.1.10", "dstIp": "10.30.1.10"},
    )
    output = _make_mcp_red_teamer().run(state)
    findings = output.redTeamFindings
    assert findings is not None
    # find_paths 应被调用过
    assert any(c.tool == "find_paths" for c in findings.mcp_tool_calls)
    # 至少存在一条残余攻击路径
    assert len(findings.residual_attack_paths) >= 1
    rp = findings.residual_attack_paths[0]
    assert rp.source == "10.10.1.10"
    assert rp.target == "10.30.1.10"
    assert rp.summary
    # 推荐里出现"扩展隔离范围"建议
    assert any("residual" in r.lower() or "extend isolation" in r.lower()
               for r in findings.recommended_constraints)
    # Challenge 列表中应出现 residual_path 类型
    assert any(c.type == "residual_path" for c in output.redTeamChallenges)


def test_red_teamer_recommends_ttl_and_rollback_fixes():
    """TTL 过短 + rollback 步骤为空 -> 推荐补救建议。"""
    state = _state_with_strategy(
        actions=[
            DefenseAction(type=ActionType.BLOCK_IP, target="203.0.113.9", parameters={})
        ],
        ttl=10,                # 过短
        rollback_steps=[],     # 缺步骤
        rollback_trigger="",   # 缺触发条件
    )
    output = _make_mcp_red_teamer().run(state)
    findings = output.redTeamFindings
    assert findings is not None
    recs = findings.recommended_constraints
    assert any("TTL=10s is too short" in r for r in recs)
    assert any("Rollback plan steps are empty" in r for r in recs)
    assert any("trigger condition" in r.lower() for r in recs)
    # BLOCK_IP 全量封禁也应被提示
    assert any("ports/protocols" in r.lower() or "specific ports" in r.lower() for r in recs)


def test_red_teamer_falls_back_when_mcp_path_invalid():
    """server_path 不存在时，redTeamFindings.mcp_error 有值，但流程不阻断。"""
    bad_client = TopologyMCPClient(
        enabled=True,
        mode="local",
        server_path="/nonexistent/topology-mcp-server",
    )
    rt = RedTeamerAgent(MockLLMClient(), topology_client=bad_client)
    state = _state_with_strategy(
        [DefenseAction(type=ActionType.BLOCK_IP, target="203.0.113.9", parameters={})]
    )
    output = rt.run(state)
    # 旧的规则化挑战仍然在
    titles = [c.title for c in output.redTeamChallenges]
    assert "Multi-source distributed bypass" in titles
    # findings 写明 mcp_error
    findings = output.redTeamFindings
    assert findings is not None
    assert findings.mcp_error is not None
    # MCP 调用全部失败但仍被记录为 trace
    assert all(not c.success for c in findings.mcp_tool_calls)
    # 即使 MCP 失败，TTL/rollback 这类不依赖 MCP 的建议仍会运行
    # （这里 ttl=1200 + rollback_steps=["rollback"]，理论上没有补救建议触发，
    #  所以仅验证 list 类型而非内容）
    assert isinstance(findings.recommended_constraints, list)
