from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_brain.integrations.mcp_client import TopologyMCPClient
from agent_brain.models import (
    ActionType,
    Challenge,
    DebateState,
    DebateStatus,
    DebateTurn,
    DefenseStrategy,
    MCPToolCall,
    RedTeamFindings,
    ResidualAttackPath,
    SecurityEvent,
    Severity,
)
from agent_brain.services.llm import LLMClient

logger = logging.getLogger(__name__)


def _load_prompt(name: str) -> str:
    prompt_path = Path(__file__).resolve().parent.parent / "prompts" / name
    return prompt_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 拓扑相关常量
# ---------------------------------------------------------------------------

# 与 PlannerAgent 保持一致的 src/dst 字段别名
_SRC_KEYS = ("srcIp", "sourceIp", "source_ip")
_DST_KEYS = ("dstIp", "targetIp", "target_ip")

# 哪些 ActionType 视为"破坏性 / 强阻断"，需要重点拓扑评估
_BLOCK_LIKE_ACTIONS = {
    ActionType.BLOCK_IP,
    ActionType.ISOLATE_POD,
    ActionType.ISOLATE_HOST,
    ActionType.RESTRICT_EGRESS,
    ActionType.APPLY_FIREWALL_RULE,
}

# 视为"业务关键"的跨域路径类型（来自 topology_service.evaluate_strategy_impact）
_CRITICAL_PATH_TYPES = {"DMZ_TO_DATABASE", "INTERNAL_TO_DATABASE"}

# TTL 合理范围（秒），超出范围会触发 Red-Team 提醒
_TTL_TOO_SHORT = 60
_TTL_TOO_LONG = 7 * 24 * 3600  # 7 天


class RedTeamerAgent:
    """Red-Team 智能体。

    本次第二阶段改造：在原有规则化挑战之外，叠加基于 ``TopologyMCPClient``
    的拓扑层挑战，包括：

    1. ``evaluate_strategy_impact`` 评估策略对全网拓扑的破坏面；
    2. 对每个破坏性动作目标调 ``get_neighbors`` 检查横向移动相邻资产；
    3. 若事件含 src/dst，则调 ``find_paths`` 检查"策略生效后是否仍存在
       完整 source->target 攻击路径"，得到 ``residual_attack_paths``；
    4. 综合输出 ``business_impact_risks`` / ``recommended_constraints``。

    设计要点同 PlannerAgent：异常隔离、ENABLE_MCP=false 时完全沿用旧规则。
    """

    def __init__(
        self,
        llm: LLMClient,
        topology_client: TopologyMCPClient | None = None,
    ) -> None:
        self.llm = llm
        self.system_prompt = _load_prompt("red_teamer_prompt.txt")
        # 与 PlannerAgent 同模式：默认按 ENABLE_MCP 自动构造
        self.topology_client = topology_client or TopologyMCPClient()

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def run(self, state: DebateState) -> DebateState:
        # 1) 拓扑层 findings：MCP 不可用时返回空 findings
        findings = self._collect_topology_findings(state)

        # 2) 原规则化挑战（保持旧行为）
        llm_hint = self.llm.generate(
            system_prompt=self.system_prompt,
            user_prompt=self._build_llm_user_prompt(state, findings),
        )
        base_challenges = self._build_challenges(state, llm_hint)

        # 3) 把拓扑发现转成 Challenge 并入 redTeamChallenges
        topo_challenges = self._build_topology_challenges(findings)
        merged_titles = {c.title for c in base_challenges}
        for tc in topo_challenges:
            if tc.title not in merged_titles:
                base_challenges.append(tc)
                merged_titles.add(tc.title)

        state.redTeamChallenges = base_challenges
        state.redTeamFindings = findings
        state.status = DebateStatus.NEEDS_REVISION
        # 兼容直接喂入 Red-Teamer 的测试场景（state.round 可能仍为 0），
        # 真实工作流由 Planner 先把 round 推到 >= 1。
        state.history.append(
            DebateTurn(
                round=max(1, state.round),
                actor="Red-Teamer",
                message=(
                    f"Generated {len(state.redTeamChallenges)} structured challenges; "
                    f"topology_findings={len(findings.topology_based_findings)}, "
                    f"residual_paths={len(findings.residual_attack_paths)}, "
                    f"recommendations={len(findings.recommended_constraints)}"
                ),
                timestamp=datetime.now(UTC),
            )
        )
        return state

    # ------------------------------------------------------------------
    # 拓扑 findings 采集（同步入口 + asyncio 桥接）
    # ------------------------------------------------------------------

    def _collect_topology_findings(self, state: DebateState) -> RedTeamFindings:
        """采集 MCP 拓扑层 findings；任何异常都被兜底为空 findings + mcp_error。"""
        strategy = state.plannerProposal
        if strategy is None:
            return RedTeamFindings()

        if not self.topology_client.enabled:
            return RedTeamFindings(
                mcp_error="MCP disabled (ENABLE_MCP=false)",
            )

        try:
            return asyncio.run(
                self._collect_topology_findings_async(strategy, state.securityEvent)
            )
        except Exception as exc:  # noqa: BLE001 — 任何异常都不能阻断 Red-Team
            logger.exception("red-team: MCP topology analysis failed")
            return RedTeamFindings(
                mcp_error=f"{exc.__class__.__name__}: {exc}",
            )

    async def _collect_topology_findings_async(
        self,
        strategy: DefenseStrategy,
        event: SecurityEvent,
    ) -> RedTeamFindings:
        """实际跑一遍 evaluate_strategy_impact / get_neighbors / find_paths。"""
        calls: list[MCPToolCall] = []
        topo_findings: list[str] = []
        residual_paths: list[ResidualAttackPath] = []
        business_risks: list[str] = []
        last_error: str | None = None

        # 收集策略中"破坏性 action"的目标，便于后续推演残余路径
        block_targets = self._extract_block_targets(strategy)

        async with self.topology_client as client:
            # ---------- 1) 拓扑层影响评估 ----------
            impact_data: dict[str, Any] | None = None
            res = await client.evaluate_strategy_impact(strategy.model_dump(mode="json"))
            calls.append(
                MCPToolCall(
                    tool="evaluate_strategy_impact",
                    arguments={"strategyId": strategy.strategyId},
                    success=res["success"],
                    summary=self._summarize_impact(res),
                )
            )
            if res["success"]:
                impact_data = res["data"]
                topo_findings.extend(self._derive_findings_from_impact(impact_data))
                business_risks.extend(self._derive_business_risks(impact_data))
            else:
                last_error = res["message"]

            # ---------- 2) 每个破坏性 action 的邻居展开 ----------
            seen_targets: set[str] = set()
            for action_type, target in block_targets:
                if not target or target in seen_targets:
                    continue
                seen_targets.add(target)
                neighbor_res = await client.get_neighbors(target)
                calls.append(
                    MCPToolCall(
                        tool="get_neighbors",
                        arguments={"ip_or_asset_id": target, "action": action_type.value},
                        success=neighbor_res["success"],
                        summary=self._summarize_neighbors(target, neighbor_res),
                    )
                )
                if neighbor_res["success"]:
                    self._derive_findings_from_neighbors(
                        action_type=action_type,
                        target=target,
                        data=neighbor_res["data"] or {},
                        topo_findings=topo_findings,
                    )

            # ---------- 3) 残余攻击路径检查 ----------
            src_ip, dst_ip = self._extract_src_dst(event)
            if src_ip and dst_ip:
                paths_res = await client.find_paths(src_ip, dst_ip)
                calls.append(
                    MCPToolCall(
                        tool="find_paths",
                        arguments={"source": src_ip, "target": dst_ip, "max_depth": 4},
                        success=paths_res["success"],
                        summary=self._summarize_paths(src_ip, dst_ip, paths_res),
                    )
                )
                if paths_res["success"]:
                    residual_paths.extend(
                        self._derive_residual_paths(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            paths=(paths_res["data"] or {}).get("paths") or [],
                            block_targets=block_targets,
                        )
                    )
                else:
                    last_error = paths_res["message"]

        # ---------- 4) 推荐约束 ----------
        recommendations = self._build_recommended_constraints(
            strategy=strategy,
            impact=impact_data,
            residual_paths=residual_paths,
            business_risks=business_risks,
        )

        any_success = any(c.success for c in calls)
        return RedTeamFindings(
            topology_based_findings=topo_findings,
            residual_attack_paths=residual_paths,
            business_impact_risks=business_risks,
            recommended_constraints=recommendations,
            mcp_tool_calls=calls,
            mcp_error=last_error if not any_success else None,
        )

    # ------------------------------------------------------------------
    # 拓扑 findings 解析辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_block_targets(
        strategy: DefenseStrategy,
    ) -> list[tuple[ActionType, str]]:
        """提取策略中破坏性 action 的 (类型, 目标) 元组列表。"""
        out: list[tuple[ActionType, str]] = []
        for act in strategy.actions:
            if act.type in _BLOCK_LIKE_ACTIONS and act.target:
                out.append((act.type, str(act.target)))
        return out

    @staticmethod
    def _extract_src_dst(event: SecurityEvent) -> tuple[str | None, str | None]:
        ctx = event.context or {}
        src = next((str(ctx[k]) for k in _SRC_KEYS if ctx.get(k)), None)
        dst = next((str(ctx[k]) for k in _DST_KEYS if ctx.get(k)), None)
        return src, dst

    @staticmethod
    def _summarize_impact(res: dict[str, Any]) -> str:
        if not res["success"]:
            return f"evaluate_strategy_impact failed: {res['message']}"
        d = res["data"] or {}
        s = d.get("summary") or {}
        return (
            f"impact_level={d.get('impact_level')}; "
            f"affected_assets={s.get('affected_asset_count')}; "
            f"affected_paths={s.get('affected_path_count')}"
        )

    @staticmethod
    def _summarize_neighbors(target: str, res: dict[str, Any]) -> str:
        if not res["success"]:
            return f"get_neighbors {target} failed: {res['message']}"
        d = res["data"] or {}
        return f"neighbors of {target}: {d.get('neighbor_count', 0)}"

    @staticmethod
    def _summarize_paths(src: str, dst: str, res: dict[str, Any]) -> str:
        if not res["success"]:
            return f"find_paths {src}->{dst} failed: {res['message']}"
        d = res["data"] or {}
        return f"find_paths {src}->{dst}: {d.get('path_count', 0)} path(s)"

    @staticmethod
    def _derive_findings_from_impact(impact: dict[str, Any]) -> list[str]:
        """从 evaluate_strategy_impact 结果中抽取拓扑发现。"""
        findings: list[str] = []
        level = impact.get("impact_level", "LOW")
        findings.append(f"strategy impact level evaluated as {level}")
        # 关键资产被命中
        crit = [
            a for a in (impact.get("affected_assets") or [])
            if str(a.get("criticality", "")).upper() == "CRITICAL"
        ]
        if crit:
            ids = ", ".join(a.get("asset_id", "?") for a in crit[:5])
            findings.append(f"strategy directly impacts CRITICAL assets: {ids}")
        # 关键业务路径被破坏
        for p in (impact.get("affected_paths") or []):
            if p.get("path_type") in _CRITICAL_PATH_TYPES:
                findings.append(
                    f"strategy may break {p['path_type']} path "
                    f"({'->'.join(p.get('nodes', []))})"
                )
        # 推荐建议（来自 topology_service）
        rec = impact.get("recommendation")
        if rec:
            findings.append(f"topology service recommends: {rec}")
        return findings

    @staticmethod
    def _derive_business_risks(impact: dict[str, Any]) -> list[str]:
        """从 evaluate_strategy_impact 推导业务影响风险。"""
        risks: list[str] = []
        for p in (impact.get("affected_paths") or []):
            ptype = p.get("path_type", "")
            severity = str(p.get("severity", "")).upper()
            if ptype in _CRITICAL_PATH_TYPES or severity in ("HIGH", "CRITICAL"):
                nodes = "->".join(p.get("nodes", []))
                risks.append(
                    f"Legitimate business traffic on path {nodes} "
                    f"(type={ptype}, severity={severity}) may be disrupted"
                )
        # 关键资产被 ISOLATE/BLOCK：直接业务中断风险
        for a in (impact.get("affected_assets") or []):
            crit = str(a.get("criticality", "")).upper()
            effect = str(a.get("effect", "")).upper()
            if crit == "CRITICAL" and effect in ("DISRUPT", "ISOLATE", "BLOCK"):
                risks.append(
                    f"CRITICAL asset {a.get('asset_id')} would be {effect.lower()}; "
                    f"production service interruption risk"
                )
        return risks

    @staticmethod
    def _derive_findings_from_neighbors(
        action_type: ActionType,
        target: str,
        data: dict[str, Any],
        topo_findings: list[str],
    ) -> None:
        """根据邻居信息检测横向移动 / 边界泄漏风险。"""
        neighbors = data.get("neighbors") or []
        if not neighbors:
            return
        crit_neighbors = [
            n for n in neighbors
            if str((n.get("asset") or {}).get("criticality", "")).upper()
            in ("HIGH", "CRITICAL")
        ]
        if crit_neighbors:
            ids = ", ".join(
                (n.get("asset") or {}).get("asset_id", "?") for n in crit_neighbors[:3]
            )
            topo_findings.append(
                f"{action_type.value} on {target} leaves {len(crit_neighbors)} HIGH/CRITICAL "
                f"neighbor(s) exposed to lateral movement: {ids}"
            )

    @staticmethod
    def _derive_residual_paths(
        src_ip: str,
        dst_ip: str,
        paths: list[dict[str, Any]],
        block_targets: list[tuple[ActionType, str]],
    ) -> list[ResidualAttackPath]:
        """对每条 src->dst 路径，判断是否完全没有被策略 actions 覆盖。"""
        if not paths:
            return []
        target_keys = {t for _, t in block_targets if t}
        residuals: list[ResidualAttackPath] = []
        for p in paths:
            raw_nodes = p.get("nodes") or []
            # 路径节点按顺序展开（asset_id / ip 都视为节点的可能键）
            ordered_nodes: list[str] = []
            ordered_keys: list[str] = []
            for n in raw_nodes:
                if isinstance(n, dict):
                    aid = n.get("asset_id")
                    ip = n.get("ip")
                    label = aid or ip or "?"
                    ordered_nodes.append(str(label))
                    if aid:
                        ordered_keys.append(str(aid))
                    if ip:
                        ordered_keys.append(str(ip))
                else:
                    label = str(n)
                    ordered_nodes.append(label)
                    ordered_keys.append(label)
            key_set = set(ordered_keys)
            chain = " -> ".join(ordered_nodes) if ordered_nodes else f"{src_ip} -> {dst_ip}"
            # 这条路径与所有 block_targets 都不相交 -> 残余攻击路径
            if target_keys and key_set and target_keys.isdisjoint(key_set):
                residuals.append(
                    ResidualAttackPath(
                        source=src_ip,
                        target=dst_ip,
                        nodes=ordered_nodes,
                        summary=(
                            f"Path {chain} is not covered by current strategy"
                        ),
                    )
                )
            elif not target_keys:
                # 策略没有任何破坏性 action，所有路径都视为残余
                residuals.append(
                    ResidualAttackPath(
                        source=src_ip,
                        target=dst_ip,
                        nodes=ordered_nodes,
                        summary=(
                            f"Strategy has no blocking action; "
                            f"path {chain} remains open"
                        ),
                    )
                )
        return residuals

    # ------------------------------------------------------------------
    # 推荐修正约束
    # ------------------------------------------------------------------

    @staticmethod
    def _build_recommended_constraints(
        strategy: DefenseStrategy,
        impact: dict[str, Any] | None,
        residual_paths: list[ResidualAttackPath],
        business_risks: list[str],
    ) -> list[str]:
        recs: list[str] = []
        action_type_set = {a.type for a in strategy.actions}

        # 1) TTL 合理性
        ttl = strategy.ttl
        if ttl < _TTL_TOO_SHORT:
            recs.append(
                f"TTL={ttl}s is too short to be effective; "
                f"raise TTL to at least {_TTL_TOO_SHORT}s or rely on persistent rule"
            )
        elif ttl > _TTL_TOO_LONG:
            recs.append(
                f"TTL={ttl}s is excessively long; cap TTL to <= {_TTL_TOO_LONG}s "
                f"to limit collateral exposure"
            )

        # 2) Rollback plan 完整性
        rb = strategy.rollbackPlan
        if not rb or not rb.steps:
            recs.append(
                "Rollback plan steps are empty; add explicit rollback steps "
                "(e.g. remove_temporary_rules, restore_network_policy)"
            )
        if rb and not rb.triggerCondition:
            recs.append(
                "Rollback plan has no trigger condition; specify a trigger "
                "(e.g. false_positive_confirmed, business_impact_detected)"
            )

        # 3) 关键资产被破坏 -> 推荐限制范围
        if impact:
            crit_assets = [
                a for a in (impact.get("affected_assets") or [])
                if str(a.get("criticality", "")).upper() == "CRITICAL"
                and str(a.get("effect", "")).upper() in ("DISRUPT", "ISOLATE", "BLOCK")
            ]
            if crit_assets:
                recs.append(
                    "Replace ISOLATE/BLOCK on CRITICAL assets with RESTRICT_EGRESS "
                    "or APPLY_FIREWALL_RULE to keep critical services online"
                )

        # 4) 关键业务路径被影响 -> 白名单业务流量
        for p in (impact or {}).get("affected_paths") or []:
            if p.get("path_type") in _CRITICAL_PATH_TYPES:
                recs.append(
                    f"Add allowlist for legitimate {p['path_type']} traffic "
                    f"(e.g. allow specific service ports/protocols only)"
                )
                break

        # 5) BLOCK_IP 全量封禁 -> 推荐限制端口/协议
        block_ip_actions = [a for a in strategy.actions if a.type == ActionType.BLOCK_IP]
        for act in block_ip_actions:
            params = act.parameters or {}
            if not params.get("port") and not params.get("protocol"):
                recs.append(
                    f"BLOCK_IP {act.target} is full-port; restrict to specific "
                    f"ports/protocols (e.g. {{'port': 443, 'protocol': 'tcp'}}) "
                    f"to avoid blocking legitimate traffic"
                )
                break

        # 6) 残余攻击路径 -> 扩大隔离范围
        if residual_paths:
            recs.append(
                f"Found {len(residual_paths)} residual attack path(s); "
                f"extend isolation to upstream/parallel nodes or block source IP"
            )

        # 7) 业务影响风险 -> 优先源端隔离
        if business_risks:
            recs.append(
                "Prefer isolating the attack source over blocking critical "
                "destinations; consider RESTRICT_EGRESS on the source asset only"
            )

        # 8) 没有 ISOLATE/BLOCK 类动作但事件高风险 -> 提示加强
        if not (action_type_set & _BLOCK_LIKE_ACTIONS):
            recs.append(
                "Strategy contains no blocking/isolating action; add at least "
                "RESTRICT_EGRESS on the affected source asset for active containment"
            )

        return recs

    # ------------------------------------------------------------------
    # 把拓扑发现转成 Challenge（保持下游 Coordinator/Revision 兼容）
    # ------------------------------------------------------------------

    @staticmethod
    def _build_topology_challenges(findings: RedTeamFindings) -> list[Challenge]:
        out: list[Challenge] = []

        # 1) 残余攻击路径 -> HIGH 严重度（最多 3 条避免噪音）
        # title 中加入路径节点拼接的短哈希，确保多条不同路径不会被同标题合并
        for idx, rp in enumerate(findings.residual_attack_paths[:3], start=1):
            chain_hint = "->".join(rp.nodes[:6]) if rp.nodes else f"{rp.source}->{rp.target}"
            out.append(
                Challenge(
                    type="residual_path",
                    title=f"Residual attack path #{idx}: {chain_hint}",
                    description=rp.summary or f"Uncovered path via {','.join(rp.nodes[:5])}",
                    severity=Severity.HIGH,
                )
            )

        # 2) 业务影响风险 -> HIGH 严重度
        for risk in findings.business_impact_risks[:3]:
            out.append(
                Challenge(
                    type="business_impact",
                    title="Business path disruption risk",
                    description=risk,
                    severity=Severity.HIGH,
                )
            )

        # 3) 推荐约束 -> MEDIUM 严重度
        for rec in findings.recommended_constraints[:5]:
            out.append(
                Challenge(
                    type="constraint",
                    title="Recommended constraint",
                    description=rec,
                    severity=Severity.MEDIUM,
                )
            )

        # 4) 一般拓扑发现 -> MEDIUM 严重度
        for ev in findings.topology_based_findings[:3]:
            out.append(
                Challenge(
                    type="topology",
                    title="Topology-based finding",
                    description=ev,
                    severity=Severity.MEDIUM,
                )
            )

        return out

    # ------------------------------------------------------------------
    # LLM Prompt 构造（在原 prompt 基础上注入拓扑摘要，便于 LLM 协同思考）
    # ------------------------------------------------------------------

    @staticmethod
    def _build_llm_user_prompt(
        state: DebateState,
        findings: RedTeamFindings,
    ) -> str:
        proposal_json = (
            state.plannerProposal.model_dump_json() if state.plannerProposal else "{}"
        )
        if not findings.topology_based_findings and not findings.residual_attack_paths:
            return f"proposal={proposal_json}"
        topo_summary = {
            "topology_based_findings": findings.topology_based_findings[:5],
            "residual_attack_paths": [
                p.summary for p in findings.residual_attack_paths[:3]
            ],
            "business_impact_risks": findings.business_impact_risks[:3],
        }
        return (
            f"proposal={proposal_json}; "
            f"topologyAnalysis={topo_summary}"
        )

    # ------------------------------------------------------------------
    # 原规则化挑战（与改造前完全一致；保 2 个旧测试通过）
    # ------------------------------------------------------------------

    def _build_challenges(self, state: DebateState, llm_hint: str) -> list[Challenge]:
        strategy = state.plannerProposal
        if strategy is None:
            return []

        actions = strategy.actions
        action_types = [a.type for a in actions]
        action_type_set = set(action_types)
        only_block_ip = len(action_types) == 1 and action_types[0] == ActionType.BLOCK_IP
        only_waf_rule = len(action_types) == 1 and action_types[0] == ActionType.APPLY_WAF_RULE

        challenges: list[Challenge] = []

        if only_block_ip:
            challenges.append(
                Challenge(
                    type="bypass",
                    title="Multi-source distributed bypass",
                    description="Single IP blocking is weak against rotating botnet sources and proxy relays.",
                    severity=Severity.HIGH,
                )
            )

        if only_waf_rule:
            challenges.append(
                Challenge(
                    type="bypass",
                    title="Base64 encoding bypass",
                    description="If attacker encodes payload, regex-only WAF rules may fail to match malicious content.",
                    severity=Severity.HIGH,
                )
            )
            challenges.append(
                Challenge(
                    type="bypass",
                    title="Application-layer mutation bypass",
                    description="Payload fragmentation, case mutation, and double-encoding can evade narrow signatures.",
                    severity=Severity.HIGH,
                )
            )

        if ActionType.RESTRICT_EGRESS in action_type_set and ActionType.ISOLATE_POD not in action_type_set:
            challenges.append(
                Challenge(
                    type="scope",
                    title="Defense scope too narrow",
                    description="Egress-only restrictions may miss lateral movement within the cluster network plane.",
                    severity=Severity.MEDIUM,
                )
            )

        if ActionType.APPLY_WAF_RULE in action_type_set and ActionType.BLOCK_IP not in action_type_set:
            challenges.append(
                Challenge(
                    type="traffic_path",
                    title="Traffic path bypass",
                    description="Attackers can shift to alternative ingress paths (direct service exposure or internal calls).",
                    severity=Severity.HIGH,
                )
            )

        if ActionType.ALERT_ONLY in action_type_set:
            challenges.append(
                Challenge(
                    type="root_cause",
                    title="Only surface intercepted, not root cause",
                    description="Alert-only strategy does not contain attacker capability or remove exploitation entry points.",
                    severity=Severity.HIGH,
                )
            )

        # 保证挑战维度覆盖：若缺失则补充默认挑战，供 Revision 收敛
        titles = {c.title for c in challenges}
        defaults = [
            Challenge(
                type="bypass",
                title="Encoding bypass",
                description="Encoding transformations can evade simplistic string match defenses.",
                severity=Severity.MEDIUM,
            ),
            Challenge(
                type="bypass",
                title="Distributed source bypass",
                description="Multiple low-frequency sources can bypass single-indicator blocking strategy.",
                severity=Severity.MEDIUM,
            ),
            Challenge(
                type="traffic_path",
                title="Alternative traffic route",
                description="Attack flow may reroute through unprotected edge/internal paths.",
                severity=Severity.MEDIUM,
            ),
            Challenge(
                type="bypass",
                title="Application mutation bypass",
                description="Syntax mutation and protocol-level obfuscation can evade brittle application filters.",
                severity=Severity.MEDIUM,
            ),
            Challenge(
                type="scope",
                title="Defense scope too small",
                description="Current strategy may protect one node but not the blast radius around dependent services.",
                severity=Severity.MEDIUM,
            ),
            Challenge(
                type="root_cause",
                title="Root cause not eliminated",
                description="Controls may block symptoms while leaving vulnerable component/version unchanged.",
                severity=Severity.HIGH,
            ),
        ]
        for item in defaults:
            if item.title not in titles:
                challenges.append(item)

        challenges.append(
            Challenge(
                type="meta",
                title="LLM red-team hint",
                description=f"mock_hint={llm_hint[:120]}",
                severity=Severity.LOW,
            )
        )
        return challenges
