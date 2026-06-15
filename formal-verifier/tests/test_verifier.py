from formal_verifier.engine import StrategyVerifier
from formal_verifier.models import DefenseAction, DefenseStrategy, RollbackPlan, StrategyScope


def _base_strategy() -> DefenseStrategy:
    return DefenseStrategy(
        strategyId="stg-test-001",
        threatType="MALWARE",
        targetLayer="WORKLOAD",
        actions=[
            DefenseAction(
                type="RESTRICT_EGRESS",
                target="pod/payment",
                parameters={"policy": "allow-approved"},
            )
        ],
        scope=StrategyScope(assets=["pod/payment"], namespaces=["payments"], tenantId="tenant-a"),
        ttl=1800,
        rollbackPlan=RollbackPlan(planId="rb-001", steps=["rollback"], triggerCondition="manual"),
        confidence=0.8,
        rationale="test",
        generatedBy="PLANNER",
        approved=False,
    )


def test_reject_block_ip_global_scope():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = [DefenseAction(type="BLOCK_IP", target="1.2.3.4", parameters={})]
    strategy.scope.assets = ["0.0.0.0/0"]
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "R001_BLOCK_IP_GLOBAL_SCOPE" in codes


def test_reject_isolate_kube_system():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = [DefenseAction(type="ISOLATE_POD", target="pod/kube-dns", parameters={})]
    strategy.scope.namespaces = ["kube-system"]
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "R002_ISOLATE_SYSTEM_NAMESPACE" in codes


def test_reject_when_actions_empty_and_no_rollback():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = []
    strategy.rollbackPlan = None
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "R005_ROLLBACK_PLAN_REQUIRED" in codes
    assert "R006_ACTIONS_NOT_EMPTY" in codes


def test_pass_valid_strategy():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    result = verifier.verify(strategy)
    assert result.passed is True
    assert result.violatedConstraints == []


def test_reject_gateway_service_full_block_continuity():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = [
        DefenseAction(
            type="RESTRICT_EGRESS",
            target="gateway-service",
            parameters={"policy": "deny_all"},
        )
    ]
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "BC002_GATEWAY_FULL_BLOCK" in codes
    assert any("公网入口" in (v.reason or "") for v in result.violatedConstraints)


def test_reject_prod_core_service_long_isolation():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.scope.namespaces = ["prod"]
    strategy.ttl = 7200
    strategy.actions = [DefenseAction(type="ISOLATE_POD", target="payment-service", parameters={})]
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "BC004_PROD_CORE_LONG_ISOLATION" in codes


# --- A2 regression: required-policy-constraint coverage ---


def test_high_risk_action_must_have_ttl():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.ttl = None
    result = verifier.verify(strategy)
    assert result.passed is False
    assert "R004_HIGH_RISK_TTL_REQUIRED" in {v.code for v in result.violatedConstraints}


def test_strategy_must_have_rollback_plan():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.rollbackPlan = None
    result = verifier.verify(strategy)
    assert result.passed is False
    assert "R005_ROLLBACK_PLAN_REQUIRED" in {v.code for v in result.violatedConstraints}


def test_reject_core_dns_deny_all():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = [
        DefenseAction(
            type="RESTRICT_EGRESS",
            target="kube-dns",
            parameters={"policy": "deny_all"},
        )
    ]
    result = verifier.verify(strategy)
    assert result.passed is False
    codes = {v.code for v in result.violatedConstraints}
    assert "R003_DNS_DENY_ALL" in codes


def test_reject_block_ip_world_scope_variants():
    verifier = StrategyVerifier()
    strategy = _base_strategy()
    strategy.actions = [DefenseAction(type="BLOCK_IP", target="1.2.3.4", parameters={})]
    strategy.scope.assets = ["0.0.0.0/0"]
    result = verifier.verify(strategy)
    assert result.passed is False
    assert "R001_BLOCK_IP_GLOBAL_SCOPE" in {v.code for v in result.violatedConstraints}

