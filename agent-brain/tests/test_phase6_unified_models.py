"""Phase 6: 统一 MCP 数据模型的契约测试。

覆盖：
  1. 新 Pydantic 模型可正确实例化、序列化（``model_dump`` / ``model_dump_json``）。
  2. ``MCPToolCall`` 增补的 ``timestamp`` / 可空 ``summary`` 不破坏旧调用。
  3. orchestrator 输出的 ``coordinatorDecision.final_strategy`` 同时包含
     spec 要求的 snake_case 字段以及历史 camelCase 字段（向后兼容）。
"""

from __future__ import annotations

import json

from agent_brain.models import (
    ExecutionConstraint,
    FinalStrategy,
    ImpactLevel,
    MCPToolCall,
    RiskLevel,
    SafetyCheck,
    StrategyImpact,
    StrategyStatus,
    TopologyContext,
)


# ---------------------------------------------------------------------------
# 1) Pure-model serialization tests
# ---------------------------------------------------------------------------


def test_mcp_tool_call_supports_optional_summary_and_timestamp():
    """spec 要求 ``summary`` 与 ``timestamp`` 都可空。"""
    call = MCPToolCall(
        server="topology-mcp-server",
        tool="get_asset_info",
        arguments={"ip": "10.0.0.1"},
        success=True,
        summary=None,
        timestamp="2026-04-28T08:00:00Z",
    )
    payload = call.model_dump(mode="json")
    assert payload["summary"] is None
    assert payload["timestamp"] == "2026-04-28T08:00:00Z"
    # 旧调用无 timestamp 也不能破坏
    legacy = MCPToolCall(tool="ping", success=True)
    assert legacy.timestamp is None
    assert legacy.summary == ""


def test_topology_context_serializes_with_safe_defaults():
    tc = TopologyContext()
    payload = tc.model_dump(mode="json")
    # 全部默认值都必须可序列化为 JSON
    assert json.loads(json.dumps(payload)) == payload
    # 默认空状态：未开启 MCP
    assert payload["topology_context_used"] is False
    assert payload["affected_assets"] == []
    assert payload["residual_attack_paths"] == []


def test_strategy_impact_default_is_none_level():
    si = StrategyImpact()
    payload = si.model_dump(mode="json")
    assert payload["impact_level"] == ImpactLevel.NONE.value
    assert payload["risk_level"] == RiskLevel.LOW.value
    assert payload["affected_assets"] == []
    assert payload["residual_path_count"] == 0


def test_execution_constraint_minimum_only_text():
    ec = ExecutionConstraint(text="must add rollback")
    payload = ec.model_dump(mode="json")
    assert payload["text"] == "must add rollback"
    assert payload["level"] == "info"
    assert payload["source"] == "coordinator"
    assert payload["rule_id"] is None


def test_final_strategy_spec_fields_round_trip():
    """spec 要求的 13 个字段必须能在 ``FinalStrategy`` 上完整 round-trip。"""
    fs = FinalStrategy(
        strategy_id="STR-001",
        action="BLOCK_IP",
        target="1.2.3.4",
        scope={"assets": ["dmz-web-01"], "namespaces": [], "tenantId": None},
        ttl_minutes=30,
        rollback_plan={
            "planId": "RB-1",
            "steps": ["unblock"],
            "triggerCondition": "manual",
        },
        human_approval_required=False,
        auto_execution_allowed=True,
        approval_reason=[],
        execution_constraints=["ttl set"],
        safety_checks=[
            SafetyCheck(id="rollback_present", label="rollback present", passed=True)
        ],
        topology_context_summary={"topology_context_used": True},
        mcp_trace=[
            MCPToolCall(
                server="topology-mcp-server",
                tool="get_asset_info",
                arguments={"ip": "1.2.3.4"},
                success=True,
                summary="hit dmz-web-01",
                timestamp="2026-04-28T08:00:00Z",
            )
        ],
    )
    payload = fs.model_dump(mode="json")

    # spec required snake_case fields all present
    expected = {
        "strategy_id",
        "action",
        "target",
        "scope",
        "ttl_minutes",
        "rollback_plan",
        "human_approval_required",
        "auto_execution_allowed",
        "approval_reason",
        "execution_constraints",
        "safety_checks",
        "topology_context_summary",
        "mcp_trace",
    }
    assert expected.issubset(set(payload.keys()))

    # JSON serialisable end-to-end
    assert json.loads(json.dumps(payload))["mcp_trace"][0]["tool"] == "get_asset_info"


# ---------------------------------------------------------------------------
# 2) Orchestrator integration: final_strategy 同时投出 snake_case + camelCase
# ---------------------------------------------------------------------------


def _run_orchestrator_once() -> dict:
    """Reuse the same fixture as the existing envelope test."""
    from agent_brain.main import _build_mock_event
    from agent_brain.services import DebateOrchestrator, MockLLMClient

    orchestrator = DebateOrchestrator(llm=MockLLMClient())
    return orchestrator.process_event(_build_mock_event())


def test_orchestrator_final_strategy_has_phase6_snake_case_fields():
    result = _run_orchestrator_once()
    fs = result["coordinatorDecision"]["final_strategy"]

    # Phase 6 snake_case fields required by the unified contract
    for key in (
        "strategy_id",
        "action",
        "target",
        "scope",
        "ttl_minutes",
        "rollback_plan",
        "topology_context_summary",
        "mcp_trace",
        "topology_context",
        "strategy_impact",
        "execution_constraints_detailed",
    ):
        assert key in fs, f"missing Phase 6 field: {key}"

    # Phase 5 fields preserved (regression guard)
    for key in (
        "status",
        "human_approval_required",
        "auto_execution_allowed",
        "approval_reason",
        "execution_constraints",
        "safety_checks",
    ):
        assert key in fs, f"missing Phase 5 field: {key}"


def test_orchestrator_final_strategy_keeps_legacy_camelcase():
    """spec 第 5 条：不能粗暴删除旧字段，必须保留兼容。"""
    result = _run_orchestrator_once()
    fs = result["coordinatorDecision"]["final_strategy"]

    # DefenseStrategy 历史字段仍存在，旧前端 / 旧测试不破
    for key in (
        "strategyId",
        "threatType",
        "targetLayer",
        "actions",
        "ttl",
        "confidence",
        "rationale",
        "approved",
    ):
        assert key in fs, f"missing legacy camelCase field: {key}"


def test_orchestrator_phase6_projection_consistency():
    """snake_case 投影必须和 camelCase / status / 顶层 cd 一致。"""
    result = _run_orchestrator_once()
    cd = result["coordinatorDecision"]
    fs = cd["final_strategy"]

    # strategy_id 与 strategyId 同源
    assert fs["strategy_id"] == fs["strategyId"]

    # 主导动作 / 目标取自 actions[0]
    if fs["actions"]:
        assert fs["action"] == fs["actions"][0]["type"]
        assert fs["target"] == fs["actions"][0]["target"]
    else:
        assert fs["action"] is None
        assert fs["target"] is None

    # ttl_minutes 与 ttl 秒级换算一致（向下取整）
    if fs["ttl"]:
        assert fs["ttl_minutes"] == int(fs["ttl"]) // 60

    # mcp_trace / topology_context_summary 与顶层 cd 一致（自包含）
    assert fs["mcp_trace"] == cd["mcp_trace"]
    assert fs["topology_context_summary"] == cd["topology_context_summary"]

    # status 与顶层 cd.status 一致（合法枚举值）
    assert fs["status"] == cd["status"]
    assert StrategyStatus(fs["status"])  # raises if invalid

    # topology_context / strategy_impact 是结构化对象
    assert isinstance(fs["topology_context"], dict)
    assert isinstance(fs["strategy_impact"], dict)
    assert "impact_level" in fs["strategy_impact"]
    assert "risk_level" in fs["strategy_impact"]


def test_orchestrator_execution_constraints_dual_form():
    """execution_constraints (字符串数组) 与 execution_constraints_detailed (结构化) 必须并存。"""
    result = _run_orchestrator_once()
    fs = result["coordinatorDecision"]["final_strategy"]
    assert isinstance(fs["execution_constraints"], list)
    assert isinstance(fs["execution_constraints_detailed"], list)
    assert len(fs["execution_constraints"]) == len(fs["execution_constraints_detailed"])
    for raw, detailed in zip(
        fs["execution_constraints"], fs["execution_constraints_detailed"], strict=True
    ):
        assert detailed["text"] == raw
        assert detailed["level"] in {"info", "warning", "critical"}
