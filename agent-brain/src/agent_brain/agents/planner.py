from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agent_brain.integrations.mcp_client import TopologyMCPClient
from agent_brain.models import (
    ActionType,
    BlastRadius,
    DebateState,
    DebateStatus,
    DebateTurn,
    DefenseAction,
    DefenseStrategy,
    GeneratedBy,
    MCPToolCall,
    PlannerTopologyMetadata,
    RollbackPlan,
    SecurityEvent,
    StrategyScope,
    TargetLayer,
    ThreatType,
)
from agent_brain.services.llm import LLMClient

logger = logging.getLogger(__name__)


def _load_prompt(name: str) -> str:
    prompt_path = Path(__file__).resolve().parent.parent / "prompts" / name
    return prompt_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 拓扑上下文采集相关常量
# ---------------------------------------------------------------------------

# 从 SecurityEvent.context 中识别 src/dst/affected_asset 时支持的字段别名
_SRC_KEYS = ("srcIp", "sourceIp", "source_ip")
_DST_KEYS = ("dstIp", "targetIp", "target_ip")
_ASSET_KEYS = ("affectedAsset", "asset_id", "assetId")


class PlannerAgent:
    """Planner 智能体。

    本次第二阶段改造的目标是：在生成防御方案之前，先通过
    ``TopologyMCPClient`` 拉取拓扑上下文，把网络资产、邻居、关键资产、
    可达路径等信息整理成 ``PlannerTopologyMetadata``，并把它注入到
    Prompt 输入与最终的 ``DebateState.plannerMetadata`` 中。

    设计要点：
    1. 完全向后兼容：``ENABLE_MCP=false`` 或 MCP 调用失败时，原本的规则
       与 LLM hint 流程保持不变，``DefenseStrategy`` 的字段也保持不变；
    2. 异步桥接：``TopologyMCPClient`` 是 async 的，``PlannerAgent.run``
       依然保持同步签名，内部用一次 ``asyncio.run`` 集中跑完所有查询；
    3. 错误隔离：任何 MCP 异常都被 ``mcp_error`` 字段捕获，不会冒泡到
       Workflow，避免阻断后续 RedTeam / Revision / Coordinator 流程。
    """

    def __init__(
        self,
        llm: LLMClient,
        topology_client: TopologyMCPClient | None = None,
    ) -> None:
        self.llm = llm
        self.system_prompt = _load_prompt("planner_prompt.txt")
        # 不强制要求外部传入：默认按环境变量 ENABLE_MCP 自动构造一个客户端，
        # 若环境变量未启用，客户端进入 disabled 模式，所有调用都会返回失败信封，
        # PlannerAgent 会自然走原有 fallback 分支。
        self.topology_client = topology_client or TopologyMCPClient()

    class PlannerInput(BaseModel):
        """Planner 提交给 LLM 的输入结构。

        新增 ``topologyContext`` 字段后，旧字段保持兼容，未启用 MCP 时
        该字段为 ``None``，Prompt 中也不会出现拓扑相关键值。
        """

        securityEvent: Any
        retrievedContext: list[str] = Field(default_factory=list)
        topologyContext: dict[str, Any] | None = None

    class PlannerOutput(BaseModel):
        strategy: DefenseStrategy
        ruleSignals: list[str] = Field(default_factory=list)
        llmHint: str = ""
        # 内部携带，便于上层 (run) 把 metadata 同步到 DebateState
        topologyMetadata: PlannerTopologyMetadata = Field(
            default_factory=PlannerTopologyMetadata
        )

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def run(self, state: DebateState) -> DebateState:
        # 1) 先采集拓扑上下文（对 MCP 不可用 / 失败做兜底，绝不抛异常）
        metadata = self._collect_topology_metadata(state.securityEvent)

        # 2) 构造给 LLM 的输入：仅在拿到拓扑信息时才挂载 topologyContext
        topology_context_payload: dict[str, Any] | None = None
        if metadata.topology_context_used:
            topology_context_payload = {
                "affected_assets": metadata.affected_assets,
                "expected_blast_radius": metadata.expected_blast_radius.value,
                "topology_evidence": metadata.topology_evidence,
            }

        planner_input = self.PlannerInput(
            securityEvent=state.securityEvent.model_dump(mode="json"),
            retrievedContext=state.retrievedContext,
            topologyContext=topology_context_payload,
        )
        llm_hint = self.llm.generate(
            system_prompt=self.system_prompt,
            user_prompt=planner_input.model_dump_json(),
        )

        # 3) 基于规则 + 拓扑上下文生成策略
        planner_output = self._generate_strategy(state, llm_hint, metadata)

        # 4) 写回 DebateState：策略 + metadata + 调试历史
        state.round += 1
        state.status = DebateStatus.IN_PROGRESS
        state.plannerProposal = planner_output.strategy
        state.plannerMetadata = planner_output.topologyMetadata
        state.history.append(
            DebateTurn(
                round=state.round,
                actor="Planner",
                message=(
                    f"Generated P1 with signals={planner_output.ruleSignals}; "
                    f"topology_context_used="
                    f"{planner_output.topologyMetadata.topology_context_used}; "
                    f"blast_radius="
                    f"{planner_output.topologyMetadata.expected_blast_radius.value}"
                ),
                timestamp=datetime.now(UTC),
            )
        )
        return state

    # ------------------------------------------------------------------
    # 拓扑上下文采集（对外暴露同步接口，内部桥接到 async client）
    # ------------------------------------------------------------------

    def _collect_topology_metadata(
        self, event: SecurityEvent
    ) -> PlannerTopologyMetadata:
        """采集 MCP 拓扑上下文，永远返回一个有效的 metadata 对象。"""
        src_ip, dst_ip, asset_id = self._extract_topology_keys(event)

        # 没有任何可用线索：直接走原 fallback，不发起任何 MCP 调用
        if not any((src_ip, dst_ip, asset_id)):
            logger.debug("planner: no topology keys in event %s, skip MCP", event.eventId)
            return PlannerTopologyMetadata(topology_context_used=False)

        # MCP 主开关关闭时，记录原因但不真正调用
        if not self.topology_client.enabled:
            return PlannerTopologyMetadata(
                topology_context_used=False,
                mcp_error="MCP disabled (ENABLE_MCP=false)",
            )

        try:
            return asyncio.run(
                self._collect_topology_metadata_async(src_ip, dst_ip, asset_id)
            )
        except Exception as exc:  # 兜底：客户端构造、事件循环异常等都不应阻断
            logger.exception("planner: MCP topology collection failed")
            return PlannerTopologyMetadata(
                topology_context_used=False,
                mcp_error=f"{exc.__class__.__name__}: {exc}",
            )

    async def _collect_topology_metadata_async(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        asset_id: str | None,
    ) -> PlannerTopologyMetadata:
        """实际跑一遍 6 个 MCP 工具调用，整理成 metadata。"""
        calls: list[MCPToolCall] = []
        evidence: list[str] = []
        affected: list[str] = []
        critical_hit = False
        high_hit = False
        path_to_db = False
        last_error: str | None = None

        client = self.topology_client
        try:
            async with client:
                # ---------- 1) src/dst/affected_asset 三个资产查询 ----------
                src_asset = await self._fetch_asset(client, src_ip, "src_ip", calls, evidence)
                dst_asset = await self._fetch_asset(client, dst_ip, "dst_ip", calls, evidence)
                affected_asset = (
                    await self._fetch_asset(
                        client, asset_id, "affected_asset", calls, evidence
                    )
                    if asset_id and asset_id not in (src_ip, dst_ip)
                    else None
                )

                for asset in (src_asset, dst_asset, affected_asset):
                    if asset is None:
                        continue
                    aid = asset.get("asset_id")
                    if aid and aid not in affected:
                        affected.append(aid)
                    crit = str(asset.get("criticality", "")).upper()
                    if crit == "CRITICAL":
                        critical_hit = True
                    elif crit == "HIGH":
                        high_hit = True

                # ---------- 2) 目的资产邻居 ----------
                if dst_ip:
                    res = await client.get_neighbors(dst_ip)
                    summary = self._summarize_neighbors(res)
                    calls.append(
                        MCPToolCall(
                            tool="get_neighbors",
                            arguments={"ip_or_asset_id": dst_ip},
                            success=res["success"],
                            summary=summary,
                        )
                    )
                    if res["success"]:
                        evidence.append(summary)
                        for n in res["data"].get("neighbors", []) or []:
                            n_asset = n.get("asset", {}) or {}
                            n_id = n_asset.get("asset_id")
                            n_crit = str(n_asset.get("criticality", "")).upper()
                            if n_id and n_id not in affected:
                                affected.append(n_id)
                            if n_crit == "CRITICAL":
                                critical_hit = True
                            elif n_crit == "HIGH":
                                high_hit = True
                    else:
                        last_error = res["message"]

                # ---------- 3) 关键资产清单 ----------
                res = await client.get_critical_assets()
                summary = self._summarize_critical(res)
                calls.append(
                    MCPToolCall(
                        tool="get_critical_assets",
                        arguments={},
                        success=res["success"],
                        summary=summary,
                    )
                )
                if res["success"]:
                    evidence.append(summary)
                else:
                    last_error = res["message"]

                # ---------- 4) src->dst 路径 ----------
                if src_ip and dst_ip:
                    res = await client.find_paths(src_ip, dst_ip)
                    summary = self._summarize_paths(res, src_ip, dst_ip)
                    calls.append(
                        MCPToolCall(
                            tool="find_paths",
                            arguments={
                                "source": src_ip,
                                "target": dst_ip,
                                "max_depth": 4,
                            },
                            success=res["success"],
                            summary=summary,
                        )
                    )
                    if res["success"]:
                        evidence.append(summary)
                        # 任意一条路径终点是 Database 区即视为命中跨域路径
                        for path in res["data"].get("paths", []) or []:
                            if any(
                                "database" in str(z).lower()
                                for z in path.get("zones", []) or []
                            ):
                                path_to_db = True
                                break
                    else:
                        last_error = res["message"]
        except Exception as exc:  # async with 自身/其它异常的兜底
            logger.exception("planner: MCP async collection error")
            last_error = f"{exc.__class__.__name__}: {exc}"

        # ---------- 5) 汇总 metadata ----------
        # 只要有任何一个 MCP 调用成功，就视为 topology_context_used=True
        any_success = any(c.success for c in calls)
        blast = self._compute_blast_radius(critical_hit, high_hit, path_to_db)
        return PlannerTopologyMetadata(
            topology_context_used=any_success,
            affected_assets=affected,
            expected_blast_radius=blast,
            topology_evidence=evidence,
            mcp_tool_calls=calls,
            mcp_error=last_error if not any_success else None,
        )

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_topology_keys(
        event: SecurityEvent,
    ) -> tuple[str | None, str | None, str | None]:
        """从 SecurityEvent.context / 顶层字段提取 src/dst/asset 三类查询键。"""
        ctx = event.context or {}
        src = next((str(ctx[k]) for k in _SRC_KEYS if ctx.get(k)), None)
        dst = next((str(ctx[k]) for k in _DST_KEYS if ctx.get(k)), None)
        asset = next((str(ctx[k]) for k in _ASSET_KEYS if ctx.get(k)), None)
        return src, dst, asset

    @staticmethod
    async def _fetch_asset(
        client: TopologyMCPClient,
        key: str | None,
        role: str,
        calls: list[MCPToolCall],
        evidence: list[str],
    ) -> dict[str, Any] | None:
        """统一的 get_asset_info 调用 + trace 记录辅助函数。"""
        if not key:
            return None
        res = await client.get_asset_info(key)
        if res["success"]:
            data = res["data"] or {}
            summary = (
                f"{role} {key} -> {data.get('asset_id')} "
                f"({data.get('criticality')}, zone={data.get('zone')})"
            )
        else:
            summary = f"{role} {key}: {res['message']}"
        calls.append(
            MCPToolCall(
                tool="get_asset_info",
                arguments={"ip_or_asset_id": key, "role": role},
                success=res["success"],
                summary=summary,
            )
        )
        evidence.append(summary)
        return res["data"] if res["success"] else None

    @staticmethod
    def _summarize_neighbors(res: dict[str, Any]) -> str:
        if not res["success"]:
            return f"get_neighbors failed: {res['message']}"
        data = res["data"] or {}
        crit_count = sum(
            1
            for n in (data.get("neighbors") or [])
            if str((n.get("asset") or {}).get("criticality", "")).upper()
            in ("HIGH", "CRITICAL")
        )
        return (
            f"neighbors of {data.get('asset_id')}: total={data.get('neighbor_count')}, "
            f"critical_or_high={crit_count}"
        )

    @staticmethod
    def _summarize_critical(res: dict[str, Any]) -> str:
        if not res["success"]:
            return f"get_critical_assets failed: {res['message']}"
        data = res["data"] or {}
        ids = [a.get("asset_id") for a in (data.get("assets") or [])][:5]
        return (
            f"critical assets: {data.get('count')} total; "
            f"sample={','.join(filter(None, ids))}"
        )

    @staticmethod
    def _summarize_paths(res: dict[str, Any], src: str, dst: str) -> str:
        if not res["success"]:
            return f"find_paths {src}->{dst} failed: {res['message']}"
        data = res["data"] or {}
        return f"find_paths {src}->{dst}: {data.get('path_count', 0)} path(s)"

    @staticmethod
    def _compute_blast_radius(
        critical_hit: bool, high_hit: bool, path_to_db: bool
    ) -> BlastRadius:
        """根据是否命中关键资产 / 是否打通到 Database 区，估算破坏面等级。"""
        if critical_hit or path_to_db:
            return BlastRadius.HIGH
        if high_hit:
            return BlastRadius.MEDIUM
        return BlastRadius.LOW

    # ------------------------------------------------------------------
    # 策略生成（保持原规则不变；仅在 rationale/scope 上叠加拓扑信息）
    # ------------------------------------------------------------------

    def _generate_strategy(
        self,
        state: DebateState,
        llm_hint: str,
        metadata: PlannerTopologyMetadata,
    ) -> PlannerOutput:
        event = state.securityEvent
        signals: list[str] = []
        combined = " ".join(
            [
                event.action.lower(),
                event.object.lower(),
                str(event.context.get("payload", "")).lower(),
                str(event.context.get("message", "")).lower(),
            ]
        )

        is_spawn_shell = "spawn_shell" in event.action.lower()
        has_log4j_pattern = any(
            k in combined for k in ("${jndi:", "log4j", "log4shell", "jndi:ldap")
        )

        if is_spawn_shell:
            signals.append("spawn_shell_detected")
        if has_log4j_pattern:
            signals.append("log4j_signature_detected")
        if metadata.topology_context_used:
            signals.append(
                f"topology_context_blast_{metadata.expected_blast_radius.value}"
            )

        threat_type = ThreatType.UNKNOWN
        target_layer = TargetLayer.NETWORK
        ttl = 1800
        confidence = max(0.5, event.riskScore)
        actions: list[DefenseAction] = []

        if has_log4j_pattern:
            threat_type = ThreatType.PRIVILEGE_ESCALATION
            target_layer = TargetLayer.APPLICATION
            actions.append(
                DefenseAction(
                    type=ActionType.APPLY_WAF_RULE,
                    target=event.object,
                    parameters={"signature": "log4j-jndi-rce", "mode": "block"},
                )
            )
            src_ip = event.context.get("srcIp")
            if src_ip:
                actions.append(
                    DefenseAction(
                        type=ActionType.BLOCK_IP,
                        target=str(src_ip),
                        parameters={"reason": "log4j_probe_source"},
                    )
                )
            ttl = 3600
            confidence = min(0.95, max(confidence, 0.88))

        if is_spawn_shell:
            threat_type = ThreatType.LATERAL_MOVEMENT
            target_layer = TargetLayer.WORKLOAD
            actions.insert(
                0,
                DefenseAction(
                    type=ActionType.RESTRICT_EGRESS,
                    target=event.subject,
                    parameters={"policy": "deny-all-except-approved", "durationSeconds": 1800},
                ),
            )
            actions.append(
                DefenseAction(
                    type=ActionType.ISOLATE_POD,
                    target=event.subject,
                    parameters={"quarantineNamespace": "security-quarantine"},
                )
            )
            ttl = 1800
            confidence = min(0.95, max(confidence, 0.9))

        if not actions:
            actions = [
                DefenseAction(
                    type=ActionType.ALERT_ONLY,
                    target=event.subject,
                    parameters={"reason": "insufficient_high_confidence_signals"},
                )
            ]
            threat_type = ThreatType.UNKNOWN
            target_layer = TargetLayer.ENDPOINT
            ttl = 900
            confidence = min(confidence, 0.65)
            signals.append("fallback_alert_only")

        # 拓扑上下文调整：将查询到的关联资产合并进 scope.assets，便于
        # 下游 actuator-service 在执行 / 回滚时定位影响范围。
        scope_assets: list[str] = [event.subject]
        for aid in metadata.affected_assets:
            if aid and aid not in scope_assets:
                scope_assets.append(aid)

        # 拓扑高破坏面时略微下调 confidence，让 Coordinator 更倾向触发验证 / 复议
        if metadata.expected_blast_radius == BlastRadius.HIGH:
            confidence = min(confidence, 0.85)

        strategy_id = f"stg-{event.eventId}-p1"
        rollback_id = f"rb-{event.eventId}-p1"
        rationale_parts = [
            f"rule_signals={signals}",
            f"risk={event.riskScore:.2f}",
            f"llm_hint={llm_hint[:80]}",
        ]
        if metadata.topology_context_used:
            rationale_parts.append(
                f"topology_blast_radius={metadata.expected_blast_radius.value}"
            )
            if metadata.affected_assets:
                rationale_parts.append(
                    f"topology_affected={','.join(metadata.affected_assets[:5])}"
                )
        elif metadata.mcp_error:
            rationale_parts.append(f"topology_unavailable={metadata.mcp_error}")
        rationale = "; ".join(rationale_parts)

        strategy = DefenseStrategy(
            strategyId=strategy_id,
            threatType=threat_type,
            targetLayer=target_layer,
            actions=actions,
            scope=StrategyScope(
                assets=scope_assets,
                namespaces=[str(event.context.get("namespace", "default"))],
                tenantId=str(event.context.get("tenantId", "default")),
            ),
            ttl=ttl,
            rollbackPlan=RollbackPlan(
                planId=rollback_id,
                steps=["remove_temporary_rules", "restore_network_policy", "close_incident_ticket"],
                triggerCondition="false_positive_confirmed",
            ),
            confidence=round(confidence, 2),
            rationale=rationale,
            generatedBy=GeneratedBy.PLANNER,
            approved=False,
        )
        return self.PlannerOutput(
            strategy=strategy,
            ruleSignals=signals,
            llmHint=llm_hint,
            topologyMetadata=metadata,
        )
