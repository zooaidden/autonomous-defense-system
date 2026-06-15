from __future__ import annotations

from formal_verifier.engine.mock_dependency_provider import MockDependencyProvider
from formal_verifier.models import ConstraintIssue, DefenseStrategy, RuleSeverity


class ContinuityChecker:
    """业务连续性约束检查器。"""

    LONG_ISOLATION_TTL_SECONDS = 1800

    def __init__(self, dependency_provider: MockDependencyProvider | None = None) -> None:
        self.provider = dependency_provider or MockDependencyProvider()

    def evaluate(self, strategy: DefenseStrategy) -> tuple[list[ConstraintIssue], list[ConstraintIssue], list[str]]:
        snapshot = self.provider.get_snapshot()
        violations: list[ConstraintIssue] = []
        warnings: list[ConstraintIssue] = []
        fixes: list[str] = []

        # BC001: core-dns 不允许整体阻断
        for action in strategy.actions:
            action_type = action.type.upper()
            target = action.target.lower()
            deny_all = str(action.parameters.get("policy", "")).lower() in {"deny_all", "deny-all"}
            if "core-dns" in target and action_type in {"BLOCK_IP", "RESTRICT_EGRESS"} and deny_all:
                violations.append(
                    ConstraintIssue(
                        code="BC001_CORE_DNS_BLOCKED",
                        description="core-dns 不允许被整体阻断",
                        severity=RuleSeverity.CRITICAL,
                        reason="该策略会中断集群 DNS 解析，导致全局服务发现失败。",
                    )
                )
                fixes.append("为 core-dns 设置最小放通白名单，不执行 deny all。")

        # BC002: gateway-service 不允许直接全量封禁
        for action in strategy.actions:
            action_type = action.type.upper()
            target = action.target.lower()
            if "gateway-service" in target and action_type in {"ISOLATE_POD", "RESTRICT_EGRESS"}:
                if str(action.parameters.get("policy", "")).lower() in {"deny_all", "deny-all"} or action_type == "ISOLATE_POD":
                    violations.append(
                        ConstraintIssue(
                            code="BC002_GATEWAY_FULL_BLOCK",
                            description="gateway-service 是公网入口，不允许被直接全量封禁",
                            severity=RuleSeverity.HIGH,
                            reason="公网入口全量封禁将导致业务整体不可用。",
                        )
                    )
                    fixes.append("改为细粒度规则（按恶意源/IP/路径）而非全量封禁 gateway-service。")

        # BC003: db-primary 仅允许 payment/auth 连接
        for action in strategy.actions:
            if action.type.upper() != "RESTRICT_EGRESS":
                continue
            target = action.target.lower()
            if "db-primary" not in target:
                continue
            allowed_callers = snapshot.db_allowlist.get("db-primary", set())
            denied = set(map(str.lower, action.parameters.get("denySources", [])))
            if {"payment-service", "auth-service"} & denied:
                violations.append(
                    ConstraintIssue(
                        code="BC003_DB_PRIMARY_ALLOWLIST_BROKEN",
                        description="db-primary 仅允许来自 payment-service 和 auth-service 的连接",
                        severity=RuleSeverity.CRITICAL,
                        reason="策略阻断了关键上游服务到主库链路，交易与鉴权会失败。",
                    )
                )
                fixes.append(
                    f"保持 {sorted(allowed_callers)} 到 db-primary 的连接白名单，仅阻断非授权来源。"
                )

        # BC004: prod 命名空间核心服务不能长时间隔离
        in_prod = any(ns.lower() == "prod" for ns in strategy.scope.namespaces)
        if in_prod and (strategy.ttl or 0) > self.LONG_ISOLATION_TTL_SECONDS:
            for action in strategy.actions:
                if action.type.upper() != "ISOLATE_POD":
                    continue
                if action.target in snapshot.core_services_in_prod:
                    violations.append(
                        ConstraintIssue(
                            code="BC004_PROD_CORE_LONG_ISOLATION",
                            description="prod 命名空间核心服务不能被长时间隔离",
                            severity=RuleSeverity.HIGH,
                            reason=f"目标 {action.target} 为核心服务，ttl={strategy.ttl}s 过长可能触发连续性故障。",
                        )
                    )
                    fixes.append("降低 ttl（<=1800）或改为限流/告警优先策略。")

        # BC005: payment-service 依赖 auth-service/redis-auth，阻断依赖链给 warning
        for action in strategy.actions:
            if action.type.upper() not in {"BLOCK_IP", "RESTRICT_EGRESS"}:
                continue
            target = action.target.lower()
            if any(dep in target for dep in ("auth-service", "redis-auth")):
                warnings.append(
                    ConstraintIssue(
                        code="BC005_PAYMENT_DEPENDENCY_RISK",
                        description="payment-service 依赖 auth-service 和 redis-auth",
                        severity=RuleSeverity.MEDIUM,
                        reason="当前策略可能影响支付链路鉴权与会话缓存能力。",
                    )
                )
                fixes.append("验证 payment-service 到 auth-service/redis-auth 的依赖链健康后再执行。")

        return violations, warnings, fixes

