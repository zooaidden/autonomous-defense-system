"""Unit tests for agent_brain.integrations.actuator_client.

Focus areas:
* MCP-style pre-check (rollback plan / TTL gating for high-risk actions).
* Dry-run defaulting (must default to True so a forgetful upstream cannot
  trigger a real apply by accident).
* Privilege-elevation refusal happens upstream in the executor, not here,
  so we do not test sudo refusal in this file.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from agent_brain.integrations.actuator_client import ActuatorClient
from agent_brain.models import (
    DefenseAction,
    DefenseStrategy,
    RollbackPlan,
    StrategyScope,
)


def _strategy(
    *,
    action_type: str = "RESTRICT_EGRESS",
    rollback_plan: RollbackPlan | None = None,
    ttl: int | None = 1800,
) -> DefenseStrategy:
    return DefenseStrategy(
        strategyId="stg-test-001",
        threatType="MALWARE",
        targetLayer="WORKLOAD",
        actions=[
            DefenseAction(type=action_type, target="payment-service", parameters={})
        ],
        scope=StrategyScope(
            assets=["payment-service"],
            namespaces=["payments"],
            tenantId="t-a",
        ),
        ttl=ttl,
        rollbackPlan=rollback_plan,
        confidence=0.8,
        rationale="test",
        generatedBy="PLANNER",
        approved=False,
    )


class ActuatorMcpGuardTests(unittest.TestCase):
    """The agent-brain side of the actuator MCP pre-check.

    We exercise the static ``_pre_execute_check`` helper directly so we can
    build dict payloads that violate the rules (DefenseStrategy itself
    forbids those shapes at the Pydantic layer).
    """

    def test_block_high_risk_without_rollback_plan(self) -> None:
        payload = {
            "strategyId": "stg-1",
            "actions": [{"type": "RESTRICT_EGRESS", "target": "payment-service"}],
            "ttl": 1800,
            "rollbackPlan": None,
        }
        violations, _ = ActuatorClient._pre_execute_check(payload)
        self.assertTrue(any("rollbackPlan" in v for v in violations))

    def test_block_high_risk_without_ttl(self) -> None:
        payload = {
            "strategyId": "stg-1",
            "actions": [{"type": "BLOCK_IP", "target": "1.2.3.4"}],
            "ttl": None,
            "rollbackPlan": {"planId": "rb-1"},
        }
        violations, _ = ActuatorClient._pre_execute_check(payload)
        self.assertTrue(any("ttl" in v for v in violations))

    def test_low_risk_missing_rollback_plan_is_only_warning(self) -> None:
        payload = {
            "strategyId": "stg-1",
            # ALERT_ONLY is not on the high-risk allow-list -> warning only.
            "actions": [{"type": "ALERT_ONLY", "target": "syslog"}],
            "ttl": 60,
            "rollbackPlan": None,
        }
        violations, warnings = ActuatorClient._pre_execute_check(payload)
        self.assertEqual(violations, [])
        self.assertTrue(any("rollbackPlan" in w for w in warnings))

    def test_dry_run_default_true(self) -> None:
        client = ActuatorClient(guard_enabled=True)
        plan = RollbackPlan(planId="rb-1", steps=["x"], triggerCondition="manual")
        captured: dict[str, object] = {}

        class _FakeResp:
            status_code = 200

            def raise_for_status(self) -> None:
                pass

            def json(self):
                return {"success": True, "data": {"status": "SUCCEEDED"}}

        def _capture(url, json=None, timeout=None):
            captured["json"] = json
            return _FakeResp()

        with patch(
            "agent_brain.integrations.actuator_client.httpx.post",
            side_effect=_capture,
        ):
            resp = client.submit_strategy(_strategy(rollback_plan=plan))
        self.assertTrue(captured["json"]["dryRun"])
        self.assertTrue(resp.get("dryRun"))

    def test_explicit_real_run_propagates_dry_run_false(self) -> None:
        client = ActuatorClient(guard_enabled=True)
        plan = RollbackPlan(planId="rb-1", steps=["x"], triggerCondition="manual")
        captured: dict[str, object] = {}

        class _FakeResp:
            status_code = 200

            def raise_for_status(self) -> None:
                pass

            def json(self):
                return {"success": True, "data": {"status": "SUCCEEDED"}}

        def _capture(url, json=None, timeout=None):
            captured["json"] = json
            return _FakeResp()

        with patch(
            "agent_brain.integrations.actuator_client.httpx.post",
            side_effect=_capture,
        ):
            client.submit_strategy(_strategy(rollback_plan=plan), dry_run=False)
        self.assertFalse(captured["json"]["dryRun"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
