from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from formal_verifier.models import ConstraintIssue, DefenseStrategy, RuleSeverity


@dataclass(frozen=True)
class RuleDefinition:
    code: str
    description: str
    severity: RuleSeverity
    level: str  # "violation" or "warning"
    evaluator: Callable[[DefenseStrategy], bool]  # True means rule hit
    suggested_fix: str


class StaticRuleEngine:
    """静态规则引擎，可扩展为 Z3/OPA 混合求解前置层。"""

    HIGH_RISK_ACTIONS = {"BLOCK_IP", "RESTRICT_EGRESS", "APPLY_WAF_RULE", "ISOLATE_POD"}

    def __init__(self) -> None:
        self.rules = [
            RuleDefinition(
                code="R001_BLOCK_IP_GLOBAL_SCOPE",
                description="不允许 scope 为 0.0.0.0/0 且动作为 block_ip",
                severity=RuleSeverity.HIGH,
                level="violation",
                evaluator=self._rule_block_ip_global_scope,
                suggested_fix="将 scope 缩小到具体源/网段，不要使用 0.0.0.0/0。",
            ),
            RuleDefinition(
                code="R002_ISOLATE_SYSTEM_NAMESPACE",
                description="不允许对 kube-system 命名空间执行 isolate_pod",
                severity=RuleSeverity.CRITICAL,
                level="violation",
                evaluator=self._rule_isolate_kube_system,
                suggested_fix="将命名空间从 kube-system 移除，改为业务命名空间隔离。",
            ),
            RuleDefinition(
                code="R003_DNS_DENY_ALL",
                description="不允许对 DNS 核心服务直接执行 deny all",
                severity=RuleSeverity.CRITICAL,
                level="violation",
                evaluator=self._rule_dns_core_deny_all,
                suggested_fix="为 DNS 服务设置最小放通策略，不要 deny all。",
            ),
            RuleDefinition(
                code="R004_HIGH_RISK_TTL_REQUIRED",
                description="所有高风险动作必须设置 ttl",
                severity=RuleSeverity.HIGH,
                level="violation",
                evaluator=self._rule_high_risk_requires_ttl,
                suggested_fix="为高风险动作策略设置合理 ttl（如 900~3600 秒）。",
            ),
            RuleDefinition(
                code="R005_ROLLBACK_PLAN_REQUIRED",
                description="所有策略必须包含 rollbackPlan",
                severity=RuleSeverity.HIGH,
                level="violation",
                evaluator=self._rule_rollback_required,
                suggested_fix="补充 rollbackPlan（planId、steps、triggerCondition）。",
            ),
            RuleDefinition(
                code="R006_ACTIONS_NOT_EMPTY",
                description="策略 action 不能为空",
                severity=RuleSeverity.HIGH,
                level="violation",
                evaluator=self._rule_actions_not_empty,
                suggested_fix="至少定义一个可执行动作。",
            ),
        ]

    def evaluate(self, strategy: DefenseStrategy) -> tuple[list[ConstraintIssue], list[ConstraintIssue], list[str]]:
        violations: list[ConstraintIssue] = []
        warnings: list[ConstraintIssue] = []
        fixes: list[str] = []

        for rule in self.rules:
            if not rule.evaluator(strategy):
                continue
            issue = ConstraintIssue(code=rule.code, description=rule.description, severity=rule.severity)
            if rule.level == "warning":
                warnings.append(issue)
            else:
                violations.append(issue)
            fixes.append(rule.suggested_fix)
        return violations, warnings, fixes

    def _rule_block_ip_global_scope(self, strategy: DefenseStrategy) -> bool:
        has_block_ip = any(a.type.upper() == "BLOCK_IP" for a in strategy.actions)
        global_scope = "0.0.0.0/0" in strategy.scope.assets
        return has_block_ip and global_scope

    def _rule_isolate_kube_system(self, strategy: DefenseStrategy) -> bool:
        has_isolate_pod = any(a.type.upper() == "ISOLATE_POD" for a in strategy.actions)
        is_kube_system = any(ns.lower() == "kube-system" for ns in strategy.scope.namespaces)
        return has_isolate_pod and is_kube_system

    def _rule_dns_core_deny_all(self, strategy: DefenseStrategy) -> bool:
        dns_targets = {"kube-dns", "coredns", "dns-core", "dns"}
        for action in strategy.actions:
            action_type = action.type.upper()
            target = action.target.lower()
            deny_all = str(action.parameters.get("policy", "")).lower() in {"deny_all", "deny-all"}
            if action_type == "RESTRICT_EGRESS" and deny_all and any(d in target for d in dns_targets):
                return True
        return False

    def _rule_high_risk_requires_ttl(self, strategy: DefenseStrategy) -> bool:
        has_high_risk = any(a.type.upper() in self.HIGH_RISK_ACTIONS for a in strategy.actions)
        return has_high_risk and (strategy.ttl is None or strategy.ttl <= 0)

    def _rule_rollback_required(self, strategy: DefenseStrategy) -> bool:
        return strategy.rollbackPlan is None

    def _rule_actions_not_empty(self, strategy: DefenseStrategy) -> bool:
        return len(strategy.actions) == 0

