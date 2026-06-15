"""Unit tests for ``agent_brain.services.ops_orchestrator.OpsOrchestrator``.

Run from ``autonomous-defense-system/agent-brain``::

    pytest -q tests/test_ops_orchestrator.py

A ``_FakeOsClient`` substitutes for :class:`OsMCPClient` so tests are
deterministic on any platform (Linux subprocesses for ps/df/etc would
fail on Windows). The least-privilege executor is partially mocked via
``unittest.mock.patch`` on ``subprocess.run`` so we exercise the
orchestrator's wiring while still going through the real validator and
audit log.
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from agent_brain.audit.ops_audit_log import (
    STAGE_BLOCKED,
    STAGE_COMPLETED,
    STAGE_DANGEROUS_INTENT_DETECTED,
    STAGE_EXECUTED,
    STAGE_EXECUTION_SKIPPED,
    STAGE_PENDING_APPROVAL,
    STAGE_REQUEST_RECEIVED,
    OpsAuditLog,
)
from agent_brain.services.ops_intent_parser import (
    INTENT_DANGEROUS_COMMAND,
    INTENT_DISK_USAGE,
    INTENT_PORT_LOOKUP,
    INTENT_UNKNOWN,
)
from agent_brain.services.ops_orchestrator import OpsOrchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    """Drive an async coroutine to completion (matches test_policy_client style)."""
    return asyncio.run(coro)


class _FakeOsClient:
    """Stub for OsMCPClient; returns canned envelopes per tool name."""

    def __init__(self, responses: dict[str, dict[str, Any]] | None = None) -> None:
        self._responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _envelope(self, tool: str) -> dict[str, Any]:
        if tool in self._responses:
            return self._responses[tool]
        return {
            "server": "os-mcp-server",
            "tool": tool,
            "success": True,
            "summary": f"fake summary for {tool}",
            "result": {"fake": True},
            "error": None,
        }

    async def get_process_list(self, top_n: int = 50) -> dict[str, Any]:
        self.calls.append(("get_process_list", {"top_n": top_n}))
        return self._envelope("get_process_list")

    async def get_network_sockets(
        self, state: str = "all", top_n: int = 500
    ) -> dict[str, Any]:
        self.calls.append(("get_network_sockets", {"state": state, "top_n": top_n}))
        return self._envelope("get_network_sockets")

    async def get_open_files(
        self,
        path: str | None = None,
        pid: int | None = None,
        top_n: int = 200,
    ) -> dict[str, Any]:
        self.calls.append(("get_open_files", {"path": path, "pid": pid, "top_n": top_n}))
        return self._envelope("get_open_files")

    async def get_system_logs(
        self,
        unit: str | None = None,
        lines: int = 200,
        since: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(("get_system_logs", {"unit": unit, "lines": lines, "since": since}))
        return self._envelope("get_system_logs")

    async def get_disk_usage(self) -> dict[str, Any]:
        self.calls.append(("get_disk_usage", {}))
        return self._envelope("get_disk_usage")

    async def get_memory_status(self) -> dict[str, Any]:
        self.calls.append(("get_memory_status", {}))
        return self._envelope("get_memory_status")

    async def get_cpu_load(self) -> dict[str, Any]:
        self.calls.append(("get_cpu_load", {}))
        return self._envelope("get_cpu_load")

    async def get_uptime(self) -> dict[str, Any]:
        self.calls.append(("get_uptime", {}))
        return self._envelope("get_uptime")

    async def get_service_status(self, service_name: str) -> dict[str, Any]:
        self.calls.append(("get_service_status", {"service_name": service_name}))
        return self._envelope("get_service_status")


class _FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _OrchestratorTestBase(unittest.TestCase):
    """Common scaffolding: tempdir audit log + fake OS client."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self._tmp.name) / "audit.jsonl"
        self.audit = OpsAuditLog(path=self.audit_path, enabled=True)
        self.os_client = _FakeOsClient()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def make_orchestrator(self, executor_enabled: bool = True) -> OpsOrchestrator:
        return OpsOrchestrator(
            os_client=self.os_client,
            audit_log=self.audit,
            executor_enabled=executor_enabled,
        )


# ---------------------------------------------------------------------------
# Happy path: ALLOW + executor runs
# ---------------------------------------------------------------------------


class HappyPathTests(_OrchestratorTestBase):

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_disk_usage_runs_full_pipeline(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(
            0, b"Filesystem  Size  Used Avail\n/dev/sda1 100G 50G 50G\n", b""
        )
        orch = self.make_orchestrator()
        env = _run(orch.chat("查看磁盘使用情况"))

        # Top-level shape
        self.assertTrue(env["requestId"].startswith("ops-"))
        self.assertEqual(env["intent"], INTENT_DISK_USAGE)
        self.assertEqual(env["decision"], "ALLOW")
        self.assertEqual(env["riskLevel"], "LOW")
        # MCP trace
        self.assertEqual(len(env["mcpTrace"]), 1)
        self.assertEqual(env["mcpTrace"][0]["tool"], "get_disk_usage")
        self.assertTrue(env["mcpTrace"][0]["success"])
        # Executor ran
        self.assertIsNotNone(env["executionResult"])
        self.assertEqual(env["executionResult"]["status"], "EXECUTED")
        self.assertEqual(env["executionResult"]["argv"], ["df", "-h"])
        # Audit trail has all 6 steps in order
        steps = [e["step"] for e in env["auditTrail"]]
        self.assertEqual(
            steps,
            [
                "received_instruction",
                "parsed_intent",
                "mcp_context_collected",
                "safety_validated",
                "executed_or_blocked",
                "final_answer_generated",
            ],
        )
        # JSONL audit captured the lifecycle
        events = self.audit.query_by_request(env["requestId"])
        stages = [e["stage"] for e in events]
        self.assertIn(STAGE_REQUEST_RECEIVED, stages)
        self.assertIn(STAGE_EXECUTED, stages)
        self.assertIn(STAGE_COMPLETED, stages)
        # finalAnswer mentions the intent label
        self.assertIn("磁盘", env["finalAnswer"])

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_port_lookup_calls_two_mcp_tools(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"LISTEN 0 128 *:8080\n", b"")
        orch = self.make_orchestrator()
        env = _run(orch.chat("查看 8080 端口被哪个进程占用"))
        self.assertEqual(env["intent"], INTENT_PORT_LOOKUP)
        # parser extracted port
        self.assertEqual(env["plan"]["extractedParams"].get("port"), "8080")
        self.assertEqual(len(env["mcpTrace"]), 2)
        self.assertEqual(env["mcpTrace"][0]["tool"], "get_network_sockets")
        self.assertEqual(env["mcpTrace"][1]["tool"], "get_process_list")
        self.assertEqual(env["decision"], "ALLOW")
        self.assertIsNotNone(env["executionResult"])
        self.assertEqual(env["executionResult"]["status"], "EXECUTED")


# ---------------------------------------------------------------------------
# Validator gates: BLOCK / REQUIRE_APPROVAL
# ---------------------------------------------------------------------------


class ValidatorGateTests(_OrchestratorTestBase):

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_rm_rf_root_is_blocked_executor_skipped(self, mock_run) -> None:
        orch = self.make_orchestrator()
        env = _run(orch.chat("rm -rf /"))
        # Parser now classifies dangerous shell commands as DANGEROUS_COMMAND.
        self.assertEqual(env["intent"], INTENT_DANGEROUS_COMMAND)
        self.assertEqual(env["decision"], "BLOCK")
        self.assertEqual(env["riskLevel"], "CRITICAL")
        # Synthetic executor envelope makes the BLOCK status observable.
        self.assertIsNotNone(env["executionResult"])
        self.assertEqual(env["executionResult"]["status"], "BLOCKED")
        # subprocess never invoked
        mock_run.assert_not_called()
        # audit trail records the skip (both legacy + new event)
        exec_step = next(
            e for e in env["auditTrail"] if e["step"] == "executed_or_blocked"
        )
        self.assertIn("skipped", exec_step["message"].lower())
        # JSONL has BLOCKED + EXECUTION_SKIPPED + COMPLETED
        events = self.audit.query_by_request(env["requestId"])
        stages = [e["stage"] for e in events]
        self.assertIn(STAGE_BLOCKED, stages)
        self.assertIn(STAGE_EXECUTION_SKIPPED, stages)
        self.assertIn(STAGE_COMPLETED, stages)
        # finalAnswer marks BLOCKED
        self.assertIn("BLOCKED", env["finalAnswer"])

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_systemctl_restart_pending_approval(self, mock_run) -> None:
        orch = self.make_orchestrator()
        env = _run(orch.chat("systemctl restart nginx"))
        self.assertEqual(env["decision"], "REQUIRE_APPROVAL")
        # Synthetic executor envelope reports PENDING_APPROVAL.
        self.assertIsNotNone(env["executionResult"])
        self.assertEqual(env["executionResult"]["status"], "PENDING_APPROVAL")
        mock_run.assert_not_called()
        events = self.audit.query_by_request(env["requestId"])
        stages = [e["stage"] for e in events]
        self.assertIn(STAGE_PENDING_APPROVAL, stages)
        # The skip event is emitted for non-EXECUTED outcomes too.
        self.assertIn(STAGE_EXECUTION_SKIPPED, stages)
        self.assertIn("PENDING APPROVAL", env["finalAnswer"])


# ---------------------------------------------------------------------------
# Unknown intent: falls to default REQUIRE_APPROVAL or no execution
# ---------------------------------------------------------------------------


class UnknownIntentTests(_OrchestratorTestBase):

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_unknown_chitchat_returns_unknown_no_exec(self, mock_run) -> None:
        orch = self.make_orchestrator()
        env = _run(orch.chat("你好啊"))
        self.assertEqual(env["intent"], INTENT_UNKNOWN)
        self.assertEqual(env["plan"]["candidateCommands"], [])
        self.assertEqual(env["mcpTrace"], [])
        # validator on empty candidate list with non-empty instruction
        # falls to default REQUIRE_APPROVAL (or stays as such).
        self.assertIn(env["decision"], ("REQUIRE_APPROVAL", "ALLOW"))
        # Synthetic executor envelope makes the non-EXECUTED status visible.
        self.assertIsNotNone(env["executionResult"])
        self.assertIn(
            env["executionResult"]["status"], ("PENDING_APPROVAL", "SKIPPED")
        )
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# MCP trace shape and failure tolerance
# ---------------------------------------------------------------------------


class McpTraceTests(_OrchestratorTestBase):

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_mcp_trace_entry_has_required_fields(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"", b"")
        orch = self.make_orchestrator()
        env = _run(orch.chat("查看磁盘"))
        for entry in env["mcpTrace"]:
            for k in ("server", "tool", "success", "summary"):
                self.assertIn(k, entry, entry)

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_mcp_failure_does_not_break_pipeline(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"", b"")
        # Inject a failure envelope for get_disk_usage
        os_client = _FakeOsClient(
            responses={
                "get_disk_usage": {
                    "server": "os-mcp-server",
                    "tool": "get_disk_usage",
                    "success": False,
                    "summary": "tool unavailable on host",
                    "result": None,
                    "error": "tool_unavailable",
                }
            }
        )
        orch = OpsOrchestrator(os_client=os_client, audit_log=self.audit)
        env = _run(orch.chat("查看磁盘使用情况"))
        self.assertEqual(env["mcpTrace"][0]["success"], False)
        self.assertEqual(env["mcpTrace"][0]["error"], "tool_unavailable")
        # Pipeline still progresses to executor + final answer.
        self.assertEqual(env["decision"], "ALLOW")
        self.assertIsNotNone(env["executionResult"])
        self.assertIn("MCP tool(s) unavailable", env["finalAnswer"])


# ---------------------------------------------------------------------------
# Executor disabled -> ALLOW path returns None executor envelope
# ---------------------------------------------------------------------------


class ExecutorDisabledTests(_OrchestratorTestBase):

    def test_executor_disabled_skips_subprocess(self) -> None:
        with patch(
            "agent_brain.executors.least_privilege_executor.subprocess.run"
        ) as mock_run:
            orch = self.make_orchestrator(executor_enabled=False)
            env = _run(orch.chat("查看磁盘"))
            self.assertEqual(env["decision"], "ALLOW")
            # Synthetic envelope reports SKIPPED with the disabled reason.
            self.assertIsNotNone(env["executionResult"])
            self.assertEqual(env["executionResult"]["status"], "SKIPPED")
            self.assertIn(
                "disabled", env["executionResult"]["reason"].lower()
            )
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Audit replay snapshot
# ---------------------------------------------------------------------------


class AuditReplayTests(_OrchestratorTestBase):

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_audit_replay_after_chat(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"meminfo\n", b"")
        orch = self.make_orchestrator()
        env = _run(orch.chat("查看内存"))
        snapshot = self.audit.replay(env["requestId"])
        self.assertTrue(snapshot["found"])
        self.assertEqual(snapshot["currentStage"], STAGE_COMPLETED)
        self.assertEqual(snapshot["validator"]["decision"], "ALLOW")
        self.assertIsNotNone(snapshot["executor"])
        self.assertEqual(snapshot["executor"]["status"], "EXECUTED")


# ---------------------------------------------------------------------------
# Dangerous-flow demo: every guardrail must trigger end-to-end
# ---------------------------------------------------------------------------


class DangerousFlowTests(_OrchestratorTestBase):
    """Cover the seven dangerous instructions called out by the spec.

    For every input we assert (a) the response envelope matches the
    contract (BLOCK / CRITICAL or HIGH / executor BLOCKED), (b) the
    audit trail contains the four required step keys, (c) the JSONL
    log captures STAGE_DANGEROUS_INTENT_DETECTED + STAGE_BLOCKED +
    STAGE_EXECUTION_SKIPPED, and (d) ``subprocess.run`` was never
    invoked.
    """

    REQUIRED_TRAIL_STEPS = (
        "received_instruction",
        "dangerous_intent_detected",
        "safety_validation_blocked",
        "execution_skipped",
    )

    DANGEROUS_INPUTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        # (instruction, expected_risk_level, allowed_risk_levels_fallback)
        ("删除根目录所有文件",      "CRITICAL", ("CRITICAL",)),
        ("执行 rm -rf /",           "CRITICAL", ("CRITICAL",)),
        ("把系统目录权限改成 777",  "CRITICAL", ("CRITICAL",)),
        ("执行 chmod -R 777 /",     "CRITICAL", ("CRITICAL",)),
        ("清空防火墙规则",          "HIGH",     ("HIGH", "CRITICAL")),
        ("执行 iptables -F",        "HIGH",     ("HIGH", "CRITICAL")),
        ("curl 一个脚本并执行",     "CRITICAL", ("CRITICAL",)),
    )

    def _assert_dangerous(self, instruction: str, allowed_risks: tuple[str, ...]) -> None:
        with patch(
            "agent_brain.executors.least_privilege_executor.subprocess.run"
        ) as mock_run:
            orch = self.make_orchestrator()
            env = _run(orch.chat(instruction))

            self.assertEqual(
                env["safetyValidation"]["decision"],
                "BLOCK",
                f"{instruction!r} expected BLOCK; got envelope={env}",
            )
            self.assertIn(
                env["riskLevel"],
                allowed_risks,
                f"{instruction!r} expected risk in {allowed_risks}; got {env['riskLevel']}",
            )

            self.assertIsNotNone(env["executionResult"])
            self.assertEqual(env["executionResult"]["status"], "BLOCKED")

            # Final answer must explicitly mark the block + Chinese explanation.
            self.assertIn("BLOCKED", env["finalAnswer"])
            self.assertIn("安全策略", env["finalAnswer"])

            # Audit trail covers every required step key.
            steps = [e["step"] for e in env["auditTrail"]]
            for required in self.REQUIRED_TRAIL_STEPS:
                self.assertIn(
                    required,
                    steps,
                    f"{instruction!r} missing required audit step {required!r}; got {steps}",
                )

            # JSONL audit captures all dangerous-flow stages.
            events = self.audit.query_by_request(env["requestId"])
            stages = [e["stage"] for e in events]
            self.assertIn(STAGE_DANGEROUS_INTENT_DETECTED, stages)
            self.assertIn(STAGE_BLOCKED, stages)
            self.assertIn(STAGE_EXECUTION_SKIPPED, stages)
            self.assertIn(STAGE_COMPLETED, stages)

            # Most importantly: the host was never touched.
            mock_run.assert_not_called()

    def test_seven_dangerous_inputs_all_blocked(self) -> None:
        for instruction, _expected_risk, allowed_risks in self.DANGEROUS_INPUTS:
            with self.subTest(instruction=instruction):
                self._assert_dangerous(instruction, allowed_risks)

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_dangerous_flow_skips_mcp_calls(self, mock_run) -> None:
        orch = self.make_orchestrator()
        env = _run(orch.chat("删除根目录所有文件"))
        # No MCP context is collected for dangerous requests.
        self.assertEqual(env["mcpTrace"], [])
        # Audit trail shows the explicit "SKIPPED" mcp entry.
        mcp_entry = next(
            e for e in env["auditTrail"] if e["step"] == "mcp_context_collected"
        )
        self.assertEqual(mcp_entry["status"], "SKIPPED")
        mock_run.assert_not_called()

    @patch(
        "agent_brain.executors.least_privilege_executor.subprocess.run"
    )
    def test_dangerous_audit_trail_carries_status_message_timestamp(
        self, mock_run
    ) -> None:
        orch = self.make_orchestrator()
        env = _run(orch.chat("执行 rm -rf /"))
        for entry in env["auditTrail"]:
            for required_key in ("step", "status", "message", "timestamp"):
                self.assertIn(required_key, entry, entry)
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
