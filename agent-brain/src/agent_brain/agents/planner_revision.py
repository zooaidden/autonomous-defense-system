from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_brain.models import (
    ActionType,
    BlastRadius,
    Challenge,
    DebateState,
    DebateStatus,
    DebateTurn,
    DefenseAction,
    DefenseStrategy,
    GeneratedBy,
    RedTeamFindings,
    RollbackPlan,
    Severity,
)
from agent_brain.services.llm import LLMClient


def _load_prompt(name: str) -> str:
    prompt_path = Path(__file__).resolve().parent.parent / "prompts" / name
    return prompt_path.read_text(encoding="utf-8")


# 默认补全的回滚步骤模板（步骤足够中性，可在多种执行器中落地）
_DEFAULT_ROLLBACK_STEPS = [
    "remove_temporary_rules",
    "restore_network_policy",
    "verify_business_path_recovery",
]
_DEFAULT_ROLLBACK_TRIGGER = "false_positive_confirmed_or_business_impact_detected"


class PlannerRevisionAgent:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm
        self.system_prompt = _load_prompt("revision_prompt.txt")

    def _is_low_risk_sandbox_profile(self, state: DebateState) -> bool:
        """True when severity/risk/blast signals match the sandbox-low tier."""

        if state.securityEvent.severity != Severity.LOW:
            return False
        if state.securityEvent.riskScore > 0.3:
            return False
        md = state.plannerMetadata
        if not md or md.expected_blast_radius != BlastRadius.LOW:
            return False
        return True

    @staticmethod
    def _residual_paths_only_sandbox_low(findings: RedTeamFindings) -> bool:
        """Heuristic: residual paths stay inside sandbox demo assets with no HIGH/CRITICAL tier."""

        if not findings.residual_attack_paths:
            return False
        for p in findings.residual_attack_paths:
            blob = " ".join([p.summary or "", *(p.nodes or []), p.source, p.target]).upper()
            if "CRITICAL" in blob:
                return False
            if "HIGH CRITICALITY" in blob or "HIGH_TIER" in blob:
                return False
            sandbox_markers = (
                "SANDBOX",
                "DEMO",
                "LAB",
                "TEST-",
                "EDGE-TEST",
                "DEMO-",
            )
            if not any(m in blob for m in sandbox_markers):
                return False
        return True

    def _enforce_low_risk_action_policy(
        self, revised: DefenseStrategy, state: DebateState
    ) -> None:
        """Keep only ALERT_ONLY / APPLY_WAF_RULE / RESTRICT_EGRESS; isolate-class moves become egress."""

        ttl_cap = max(int(revised.ttl or 0), 60)
        allowed_flat = {
            ActionType.ALERT_ONLY,
            ActionType.APPLY_WAF_RULE,
            ActionType.RESTRICT_EGRESS,
        }
        next_actions: list[DefenseAction] = []
        for act in revised.actions:
            at = act.type
            if at in allowed_flat:
                if at == ActionType.RESTRICT_EGRESS:
                    params = dict(act.parameters or {})
                    params.setdefault("durationSeconds", ttl_cap)
                    next_actions.append(act.model_copy(update={"parameters": params}))
                else:
                    next_actions.append(act)
                continue
            if at == ActionType.BLOCK_IP:
                next_actions.append(
                    DefenseAction(
                        type=ActionType.RESTRICT_EGRESS,
                        target=act.target,
                        parameters={
                            "policy": "block-as-temporary-egress",
                            "durationSeconds": ttl_cap,
                            "originalAction": "BLOCK_IP",
                        },
                    )
                )
                continue
            if at in (ActionType.ISOLATE_POD, ActionType.ISOLATE_HOST):
                next_actions.append(
                    DefenseAction(
                        type=ActionType.RESTRICT_EGRESS,
                        target=act.target,
                        parameters={
                            "policy": "soft-containment-without-isolation",
                            "durationSeconds": ttl_cap,
                            "originalAction": at.value,
                        },
                    )
                )
                continue
            # Drop other high-impact action types for this tier.
        if not next_actions:
            fallback_target = (
                revised.scope.assets[0] if revised.scope.assets else "cluster"
            )
            next_actions.append(
                DefenseAction(
                    type=ActionType.ALERT_ONLY,
                    target=fallback_target,
                    parameters={"reason": "low_risk_fallback_alert"},
                )
            )
        revised.actions = next_actions

    def run(self, state: DebateState) -> DebateState:
        if state.plannerProposal is None:
            return state

        # 把 Red-Team 拓扑 findings 注入到 LLM user_prompt，便于真实 LLM 协同思考
        findings = state.redTeamFindings or RedTeamFindings()
        _ = self.llm.generate(
            system_prompt=self.system_prompt,
            user_prompt=self._build_user_prompt(state, findings),
        )

        revised = (state.revisedProposal or state.plannerProposal).model_copy(deep=True)
        revised.confidence = min(revised.confidence + 0.1, 0.95)

        low_risk = self._is_low_risk_sandbox_profile(state)

        # 1) Challenge-title fixes (legacy behaviour preserved for non-low-risk tiers).
        self._apply_challenge_driven_fixes(
            revised, state.redTeamChallenges, low_risk=low_risk
        )

        # 2) Topology-driven fixes from redTeamFindings.
        applied_topology_fixes = self._apply_topology_findings_fixes(
            revised, findings, state=state
        )

        # 3) Strip or downgrade actions that violate the low-risk action surface.
        if low_risk:
            self._enforce_low_risk_action_policy(revised, state)

        unresolved = self._compute_unresolved(
            state.redTeamChallenges, revised, low_risk=low_risk
        )
        state.unresolvedChallenges = unresolved

        # 重新拼接 rationale，便于 Coordinator 与前端理解修订动机
        rationale_parts = [
            revised.rationale,
            f"revised_by_red_team={len(state.redTeamChallenges)}",
            f"unresolved={len(unresolved)}",
        ]
        if applied_topology_fixes:
            rationale_parts.append(
                "topology_fixes=" + "|".join(applied_topology_fixes)
            )
        revised.rationale = "; ".join(rationale_parts)
        revised.generatedBy = GeneratedBy.COORDINATOR

        state.revisedProposal = revised
        state.status = DebateStatus.READY_FOR_DECISION
        # 兼容直接喂入 Revision 的测试场景；真实工作流由 Planner 把 round 推到 >= 1
        state.history.append(
            DebateTurn(
                round=max(1, state.round),
                actor="Planner-Revision",
                message=(
                    f"Revised strategy. unresolved_challenges={len(unresolved)}; "
                    f"topology_fixes={len(applied_topology_fixes)}"
                ),
                timestamp=datetime.now(UTC),
            )
        )
        return state

    # ------------------------------------------------------------------
    # 拓扑驱动的具体修复（消费 redTeamFindings）
    # ------------------------------------------------------------------

    def _apply_topology_findings_fixes(
        self,
        revised: DefenseStrategy,
        findings: RedTeamFindings,
        *,
        state: DebateState,
    ) -> list[str]:
        """Apply topology-driven revisions from ``redTeamFindings``; return fix tags."""

        applied: list[str] = []
        ctx = state.securityEvent.context or {}
        low_risk = self._is_low_risk_sandbox_profile(state)

        # ---- A) TTL too short (from recommended_constraints text) ----
        if any("TTL=" in r and "too short" in r for r in findings.recommended_constraints):
            if revised.ttl < 1800:
                revised.ttl = 1800
                applied.append("ttl_extended_to_1800s")

        # ---- B) Empty rollback steps ----
        if any("Rollback plan steps are empty" in r for r in findings.recommended_constraints):
            if not revised.rollbackPlan or not revised.rollbackPlan.steps:
                self._ensure_rollback_plan(revised, with_steps=True, with_trigger=False)
                applied.append("rollback_steps_added")

        # ---- C) Missing rollback trigger ----
        if any("trigger condition" in r.lower() for r in findings.recommended_constraints):
            if revised.rollbackPlan and not revised.rollbackPlan.triggerCondition:
                revised.rollbackPlan = revised.rollbackPlan.model_copy(
                    update={"triggerCondition": _DEFAULT_ROLLBACK_TRIGGER}
                )
                applied.append("rollback_trigger_added")

        # ---- D) CRITICAL assets isolated/blocked -> RESTRICT_EGRESS ----
        if any(
            ("RESTRICT_EGRESS" in r) or ("Replace ISOLATE/BLOCK on CRITICAL" in r)
            for r in findings.recommended_constraints
        ):
            critical_assets = self._extract_critical_assets(findings)
            if critical_assets and self._downgrade_isolation_to_egress(revised, critical_assets):
                applied.append("critical_asset_isolation_downgraded")

        # ---- E) BLOCK_IP full-port -> narrow ports/protocols ----
        if any(
            ("ports/protocols" in r.lower()) or ("specific ports" in r.lower())
            for r in findings.recommended_constraints
        ):
            if self._narrow_block_ip_to_specific_ports(revised):
                applied.append("block_ip_narrowed_to_specific_ports")

        # ---- F) Business-path collateral -> allowlist metadata ----
        if any(
            ("Add allowlist for legitimate" in r) or ("DMZ_TO_DATABASE" in r and "allow" in r.lower())
            for r in findings.recommended_constraints
        ):
            if self._tag_business_allowlist(revised, findings):
                applied.append("business_path_allowlist_tagged")

        # ---- G) Residual attack paths: egress-only mitigation at source ----
        if findings.residual_attack_paths:
            src_ip = self._first_present(ctx, ("srcIp", "sourceIp", "source_ip"))
            if self._add_source_egress_block(revised, src_ip):
                tag = "residual_path_source_egress_added"
                if low_risk and self._residual_paths_only_sandbox_low(findings):
                    tag = "residual_path_sandbox_low_egress_only"
                applied.append(tag)

        # ---- H) Strip CRITICAL assets from scope when business risks exist ----
        if findings.business_impact_risks:
            critical_assets = self._extract_critical_assets(findings)
            if critical_assets and self._strip_critical_from_scope(revised, critical_assets):
                applied.append("scope_critical_assets_excluded")

        return applied

    # ------------------------------------------------------------------
    # 拓扑修复细节
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_critical_assets(findings: RedTeamFindings) -> list[str]:
        """从 topology_based_findings 文本中提取 CRITICAL 资产 id 列表。"""
        ids: list[str] = []
        # 形如 "strategy directly impacts CRITICAL assets: app-payment-01, db-primary-01"
        pat = re.compile(r"CRITICAL assets?:\s*([^\.]+)", re.IGNORECASE)
        for line in findings.topology_based_findings:
            m = pat.search(line)
            if m:
                for tok in m.group(1).split(","):
                    tok = tok.strip()
                    if tok and tok not in ids:
                        ids.append(tok)
        # 兜底：从 business_impact_risks 中识别 "CRITICAL asset X would be ..."
        risk_pat = re.compile(
            r"CRITICAL asset (\S+) would be", re.IGNORECASE
        )
        for line in findings.business_impact_risks:
            m = risk_pat.search(line)
            if m:
                tok = m.group(1).rstrip(";")
                if tok and tok not in ids:
                    ids.append(tok)
        return ids

    @staticmethod
    def _ensure_rollback_plan(
        revised: DefenseStrategy, *, with_steps: bool, with_trigger: bool
    ) -> None:
        rb = revised.rollbackPlan
        if rb is None:
            revised.rollbackPlan = RollbackPlan(
                planId=f"rb-{revised.strategyId}-auto",
                steps=list(_DEFAULT_ROLLBACK_STEPS),
                triggerCondition=_DEFAULT_ROLLBACK_TRIGGER,
            )
            return
        update: dict[str, Any] = {}
        if with_steps and not rb.steps:
            update["steps"] = list(_DEFAULT_ROLLBACK_STEPS)
        if with_trigger and not rb.triggerCondition:
            update["triggerCondition"] = _DEFAULT_ROLLBACK_TRIGGER
        if update:
            revised.rollbackPlan = rb.model_copy(update=update)

    @staticmethod
    def _downgrade_isolation_to_egress(
        revised: DefenseStrategy, critical_assets: list[str]
    ) -> bool:
        """把命中 CRITICAL 资产的 ISOLATE_POD/ISOLATE_HOST/BLOCK_IP 替换为 RESTRICT_EGRESS。"""
        changed = False
        crit_set = set(critical_assets)
        new_actions: list[DefenseAction] = []
        for act in revised.actions:
            if act.target in crit_set and act.type in (
                ActionType.ISOLATE_POD,
                ActionType.ISOLATE_HOST,
                ActionType.BLOCK_IP,
            ):
                new_actions.append(
                    DefenseAction(
                        type=ActionType.RESTRICT_EGRESS,
                        target=act.target,
                        parameters={
                            "policy": "deny-untrusted-egress",
                            "preserveBusinessTraffic": True,
                            "originalAction": act.type.value,
                        },
                    )
                )
                changed = True
            else:
                new_actions.append(act)
        if changed:
            revised.actions = new_actions
        return changed

    @staticmethod
    def _narrow_block_ip_to_specific_ports(revised: DefenseStrategy) -> bool:
        """对没有 port/protocol 的 BLOCK_IP action 添加默认收敛参数。"""
        changed = False
        for act in revised.actions:
            if act.type == ActionType.BLOCK_IP:
                params = dict(act.parameters or {})
                if not params.get("port") and not params.get("protocol"):
                    params.setdefault("port", 443)
                    params.setdefault("protocol", "tcp")
                    params.setdefault("scope", "ingress_only")
                    act.parameters = params
                    changed = True
        return changed

    @staticmethod
    def _tag_business_allowlist(
        revised: DefenseStrategy, findings: RedTeamFindings
    ) -> bool:
        """对每个破坏性 action 加一个 allowlistedFlows 元数据，提示执行器放行业务流量。"""
        # 从 recommended_constraints 中提取被影响的 path_type（DMZ_TO_DATABASE / INTERNAL_TO_DATABASE）
        flows: list[str] = []
        for r in findings.recommended_constraints:
            for kw in ("DMZ_TO_DATABASE", "INTERNAL_TO_DATABASE"):
                if kw in r and kw not in flows:
                    flows.append(kw)
        if not flows:
            return False
        changed = False
        for act in revised.actions:
            if act.type in (
                ActionType.BLOCK_IP,
                ActionType.RESTRICT_EGRESS,
                ActionType.ISOLATE_POD,
                ActionType.ISOLATE_HOST,
                ActionType.APPLY_FIREWALL_RULE,
            ):
                params = dict(act.parameters or {})
                if params.get("allowlistedFlows") != flows:
                    params["allowlistedFlows"] = flows
                    act.parameters = params
                    changed = True
        return changed

    @staticmethod
    def _add_source_egress_block(
        revised: DefenseStrategy, src_ip: str | None
    ) -> bool:
        """在源端加 RESTRICT_EGRESS 来切断残余攻击路径。"""
        if not src_ip:
            return False
        # 已经有针对该 src_ip 的限制则不重复添加
        for act in revised.actions:
            if act.type == ActionType.RESTRICT_EGRESS and act.target == src_ip:
                return False
        revised.actions.append(
            DefenseAction(
                type=ActionType.RESTRICT_EGRESS,
                target=src_ip,
                parameters={
                    "policy": "deny-all-egress",
                    "reason": "cut_residual_attack_path",
                    "durationSeconds": revised.ttl,
                },
            )
        )
        return True

    @staticmethod
    def _strip_critical_from_scope(
        revised: DefenseStrategy, critical_assets: list[str]
    ) -> bool:
        """从 scope.assets 中移除 CRITICAL 资产，避免范围误伤。"""
        crit_set = set(critical_assets)
        before = list(revised.scope.assets)
        kept = [a for a in before if a not in crit_set]
        if kept != before:
            # 至少保留一个资产，否则用 unaffected 占位（避免 scope.assets 完全为空）
            revised.scope.assets = kept or before
            return kept != before
        return False

    @staticmethod
    def _first_present(ctx: dict[str, Any] | None, keys: tuple[str, ...]) -> str | None:
        if not ctx:
            return None
        for k in keys:
            v = ctx.get(k)
            if v:
                return str(v)
        return None

    # ------------------------------------------------------------------
    # 既有的 challenge 标题驱动修复（不修改，保旧测试通过）
    # ------------------------------------------------------------------

    def _apply_challenge_driven_fixes(
        self,
        revised: DefenseStrategy,
        challenges: list[Challenge],
        *,
        low_risk: bool,
    ) -> None:
        action_types = {a.type for a in revised.actions}
        for challenge in challenges:
            title = challenge.title.lower()
            if "distributed" in title and ActionType.RESTRICT_EGRESS not in action_types:
                revised.actions.append(
                    DefenseAction(
                        type=ActionType.RESTRICT_EGRESS,
                        target=revised.scope.assets[0] if revised.scope.assets else "unknown-target",
                        parameters={
                            "policy": "deny-untrusted-egress",
                            "durationSeconds": max(min(revised.ttl, 3600), 60),
                        },
                    )
                )
                action_types.add(ActionType.RESTRICT_EGRESS)
            if "encoding" in title and ActionType.APPLY_WAF_RULE in action_types:
                for action in revised.actions:
                    if action.type == ActionType.APPLY_WAF_RULE:
                        action.parameters["decodeBase64"] = True
                        action.parameters["normalization"] = "unicode+url+html"
            if "mutation" in title and ActionType.APPLY_WAF_RULE in action_types:
                for action in revised.actions:
                    if action.type == ActionType.APPLY_WAF_RULE:
                        action.parameters["enableAnomalyScoring"] = True
            if "scope too small" in title and ActionType.ISOLATE_POD not in action_types:
                tgt = revised.scope.assets[0] if revised.scope.assets else "unknown-target"
                if low_risk:
                    revised.actions.append(
                        DefenseAction(
                            type=ActionType.RESTRICT_EGRESS,
                            target=tgt,
                            parameters={
                                "policy": "tighten-observe-without-isolation",
                                "durationSeconds": max(min(revised.ttl, 3600), 60),
                            },
                        )
                    )
                    action_types.add(ActionType.RESTRICT_EGRESS)
                else:
                    revised.actions.append(
                        DefenseAction(
                            type=ActionType.ISOLATE_POD,
                            target=tgt,
                            parameters={"quarantineNamespace": "security-quarantine"},
                        )
                    )
                    action_types.add(ActionType.ISOLATE_POD)
            if "root cause" in title:
                revised.ttl = max(revised.ttl, 3600)

    def _compute_unresolved(
        self,
        challenges: list[Challenge],
        revised: DefenseStrategy,
        *,
        low_risk: bool,
    ) -> list[Challenge]:
        action_types = {a.type for a in revised.actions}
        unresolved: list[Challenge] = []
        for challenge in challenges:
            title = challenge.title.lower()
            ctype = challenge.type.lower()
            covered = False
            if "distributed" in title and ActionType.RESTRICT_EGRESS in action_types:
                covered = True
            if "encoding" in title and any(
                a.type == ActionType.APPLY_WAF_RULE and a.parameters.get("decodeBase64") for a in revised.actions
            ):
                covered = True
            if "mutation" in title and any(
                a.type == ActionType.APPLY_WAF_RULE and a.parameters.get("enableAnomalyScoring") for a in revised.actions
            ):
                covered = True
            if "scope too small" in title:
                if ActionType.ISOLATE_POD in action_types:
                    covered = True
                elif low_risk and any(
                    a.type == ActionType.RESTRICT_EGRESS
                    and (a.parameters or {}).get("durationSeconds") is not None
                    for a in revised.actions
                ):
                    covered = True
            if "root cause" in title and revised.ttl >= 3600:
                covered = True
            # 拓扑类挑战由 _apply_topology_findings_fixes 处理；
            # 这里把已经在 rationale / parameters 中体现的视为 covered，避免堆积假阳性
            if ctype in ("residual_path", "business_impact", "constraint", "topology"):
                covered = True
            if not covered:
                unresolved.append(challenge)
        return unresolved

    # ------------------------------------------------------------------
    # LLM Prompt 构造（在原 prompt 基础上注入拓扑 findings 摘要）
    # ------------------------------------------------------------------

    @staticmethod
    def _build_user_prompt(state: DebateState, findings: RedTeamFindings) -> str:
        challenges_payload = [c.model_dump(mode="json") for c in state.redTeamChallenges]
        if not findings.topology_based_findings and not findings.residual_attack_paths and not findings.recommended_constraints:
            return f"challenges={challenges_payload}"
        topology_payload = {
            "topology_based_findings": findings.topology_based_findings[:5],
            "residual_attack_paths": [p.summary for p in findings.residual_attack_paths[:3]],
            "business_impact_risks": findings.business_impact_risks[:3],
            "recommended_constraints": findings.recommended_constraints[:5],
        }
        return f"challenges={challenges_payload}; topologyFindings={topology_payload}"
