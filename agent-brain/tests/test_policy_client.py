"""Unit tests for ``PolicyMCPClient``.

These tests cover the same surface as ``test_mcp_client.py`` but for the
policy-mcp-server adapter:

    * disabled mode: every method returns a failure envelope.
    * local mode: importlib-loaded ``policy_service`` is called in-process
      against the real ``policy_rules.json`` shipped in the repo.
    * real mode parsing: the ``ClientSession`` is mocked so we can verify
      that ``_parse_tool_result`` decodes structured/text content correctly
      without booting a subprocess.

Run from ``autonomous-defense-system/agent-brain``::

    pytest -q tests/test_policy_client.py
"""
from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agent_brain.integrations.policy_client import (
    MODE_DISABLED,
    MODE_LOCAL,
    MODE_REAL,
    PolicyMCPClient,
)


# Path to the in-repo policy-mcp-server. ``parents[2]`` is
# ``autonomous-defense-system/`` (consistent with test_mcp_client.py).
_FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "policy-mcp-server"
)


def _run(coro):
    """Run a coroutine in sync test bodies without pulling pytest-asyncio."""
    return asyncio.run(coro)


def _legal_strategy() -> dict:
    """Strategy that should pass all 7 rules of policy-mcp-server."""
    return {
        "strategyId": "stg-pc-legal",
        "actions": [
            {
                "type": "APPLY_WAF_RULE",
                "target": "/api/login",
                "parameters": {
                    "action": "block",
                    "path": "/api/login",
                    "rule_id": "rule-100",
                },
            }
        ],
        "scope": {"assets": ["dmz-api-01"]},
        "ttl": 1800,
        "rollbackPlan": {
            "planId": "rb",
            "steps": ["remove_rule"],
            "triggerCondition": "manual",
        },
    }


def _critical_db_block_strategy() -> dict:
    """Critical DB blocked + no human approval -> multiple violations."""
    return {
        "strategyId": "stg-pc-bad",
        "actions": [
            {"type": "BLOCK_IP", "target": "10.30.1.10", "parameters": {}}
        ],
        "scope": {"assets": ["db-primary-01"]},
        "ttl": 1800,
        "rollbackPlan": {
            "planId": "rb",
            "steps": ["restore"],
            "triggerCondition": "manual",
        },
    }


# ---------------------------------------------------------------------------
# Disabled mode
# ---------------------------------------------------------------------------


class DisabledModeTests(unittest.TestCase):
    """Every method must short-circuit to a disabled envelope."""

    def test_default_constructor_is_disabled(self) -> None:
        client = PolicyMCPClient(enabled=False)
        self.assertFalse(client.enabled)
        self.assertEqual(client.mode, MODE_DISABLED)

    def test_validate_returns_failure_envelope(self) -> None:
        client = PolicyMCPClient(enabled=False)
        result = _run(client.validate_strategy(_legal_strategy()))
        self.assertFalse(result["success"])
        self.assertIsNone(result["data"])
        self.assertIn("disabled", result["message"].lower())

    def test_check_business_constraints_disabled(self) -> None:
        client = PolicyMCPClient(enabled=False)
        result = _run(client.check_business_constraints(_legal_strategy()))
        self.assertFalse(result["success"])

    def test_require_human_approval_disabled(self) -> None:
        client = PolicyMCPClient(enabled=False)
        result = _run(client.require_human_approval(_legal_strategy()))
        self.assertFalse(result["success"])

    def test_suggest_safer_strategy_disabled(self) -> None:
        client = PolicyMCPClient(enabled=False)
        result = _run(client.suggest_safer_strategy(_legal_strategy()))
        self.assertFalse(result["success"])


# ---------------------------------------------------------------------------
# Local mode (loads the real policy_service via importlib)
# ---------------------------------------------------------------------------


class LocalModeTests(unittest.TestCase):
    """In local mode the calls hit the bundled policy_service.py."""

    def setUp(self) -> None:
        self.client = PolicyMCPClient(
            enabled=True,
            mode=MODE_LOCAL,
            server_path=_FIXTURE_SERVER_PATH,
        )

    def tearDown(self) -> None:
        _run(self.client.aclose())

    def test_mode_is_local(self) -> None:
        self.assertEqual(self.client.mode, MODE_LOCAL)
        self.assertTrue(self.client.enabled)

    def test_legal_strategy_is_valid(self) -> None:
        result = _run(self.client.validate_strategy(_legal_strategy()))
        self.assertTrue(result["success"])
        self.assertTrue(result["data"]["valid"])
        self.assertEqual(result["data"]["violations"], [])
        self.assertFalse(result["data"]["requires_human_approval"])

    def test_critical_db_block_is_invalid(self) -> None:
        result = _run(self.client.validate_strategy(_critical_db_block_strategy()))
        self.assertTrue(result["success"])
        self.assertFalse(result["data"]["valid"])
        rule_ids = {v["rule_id"] for v in result["data"]["violations"]}
        # RULE-001 (no full block on critical DB) and RULE-007 (human approval)
        # are the canonical critical-severity hits for this scenario.
        self.assertIn("RULE-001", rule_ids)
        self.assertIn("RULE-007", rule_ids)
        self.assertTrue(result["data"]["requires_human_approval"])

    def test_check_business_constraints_local(self) -> None:
        result = _run(self.client.check_business_constraints(_critical_db_block_strategy()))
        self.assertTrue(result["success"])
        self.assertFalse(result["data"]["valid"])
        rule_ids = {v["rule_id"] for v in result["data"]["violations"]}
        # RULE-003 (rollback) is NOT a business-constraint rule.
        self.assertNotIn("RULE-003", rule_ids)

    def test_require_human_approval_local(self) -> None:
        result = _run(self.client.require_human_approval(_critical_db_block_strategy()))
        self.assertTrue(result["success"])
        self.assertTrue(result["data"]["requires_human_approval"])

    def test_suggest_safer_strategy_local(self) -> None:
        result = _run(self.client.suggest_safer_strategy(_critical_db_block_strategy()))
        self.assertTrue(result["success"])
        self.assertTrue(len(result["data"]["suggestions"]) >= 1)
        # Each suggestion must be associated with a rule.
        self.assertTrue(all(s.get("rule_id") for s in result["data"]["suggestions"]))


# ---------------------------------------------------------------------------
# Local mode misconfiguration
# ---------------------------------------------------------------------------


class LocalModeBadPathTests(unittest.TestCase):
    """server_path that does not exist must surface a failure envelope."""

    def test_unknown_server_path(self) -> None:
        client = PolicyMCPClient(
            enabled=True,
            mode=MODE_LOCAL,
            server_path=Path("/nonexistent/path/policy-mcp-server"),
        )
        result = _run(client.validate_strategy(_legal_strategy()))
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["message"].lower())
        _run(client.aclose())


# ---------------------------------------------------------------------------
# Real mode (mocked ClientSession; never spawns a subprocess)
# ---------------------------------------------------------------------------


class _FakeContent:
    """Minimal stand-in for ``mcp.types.TextContent``."""

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResult:
    """Minimal stand-in for ``mcp.types.CallToolResult``."""

    def __init__(
        self,
        *,
        content: list = None,
        structuredContent: dict | None = None,
        isError: bool = False,
    ) -> None:
        self.content = content or []
        self.structuredContent = structuredContent
        self.isError = isError


class RealModeParsingTests(unittest.TestCase):
    """Drive ``_parse_tool_result`` and ``_call_real`` with a fake session."""

    def _make_client_with_session(self, session: MagicMock) -> PolicyMCPClient:
        client = PolicyMCPClient(
            enabled=True,
            mode=MODE_REAL,
            server_path=_FIXTURE_SERVER_PATH,
        )
        # Inject a pre-built session so ``_ensure_real_session`` skips the
        # subprocess + ``mcp`` package check entirely.
        client._session = session
        return client

    def test_parses_text_content_envelope(self) -> None:
        session = MagicMock()
        envelope = {
            "success": True,
            "data": {
                "valid": False,
                "violations": [{"rule_id": "RULE-001"}],
                "warnings": [],
                "requires_human_approval": True,
                "suggestions": [],
            },
            "message": "validate_strategy: valid=false",
        }
        result = _FakeResult(content=[_FakeContent(json.dumps(envelope))])

        async def fake_call_tool(name, args):
            self.assertEqual(name, "validate_strategy")
            self.assertEqual(args, {"strategy": {"strategyId": "x"}})
            return result

        session.call_tool = fake_call_tool
        client = self._make_client_with_session(session)

        out = _run(client.validate_strategy({"strategyId": "x"}))
        self.assertTrue(out["success"])
        self.assertFalse(out["data"]["valid"])
        self.assertTrue(out["data"]["requires_human_approval"])
        _run(client.aclose())

    def test_parses_structured_content(self) -> None:
        session = MagicMock()
        result = _FakeResult(
            structuredContent={
                "success": True,
                "data": {
                    "valid": True,
                    "violations": [],
                    "warnings": [],
                    "requires_human_approval": False,
                    "suggestions": [],
                },
                "message": "ok",
            }
        )

        async def fake_call_tool(name, args):
            return result

        session.call_tool = fake_call_tool
        client = self._make_client_with_session(session)

        out = _run(client.suggest_safer_strategy({"strategyId": "y"}))
        self.assertTrue(out["success"])
        self.assertTrue(out["data"]["valid"])
        _run(client.aclose())

    def test_isError_returns_failure(self) -> None:
        session = MagicMock()
        result = _FakeResult(content=[_FakeContent("boom")], isError=True)

        async def fake_call_tool(name, args):
            return result

        session.call_tool = fake_call_tool
        client = self._make_client_with_session(session)

        out = _run(client.check_business_constraints({"strategyId": "z"}))
        self.assertFalse(out["success"])
        self.assertIn("boom", out["message"])
        _run(client.aclose())


if __name__ == "__main__":
    unittest.main(verbosity=2)
