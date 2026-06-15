"""Unit tests for ``agent_brain.audit.audit_logger``.

Run from ``autonomous-defense-system/agent-brain``::

    pytest -q tests/test_audit_logger.py

Each TestCase writes into its own ``TemporaryDirectory`` so the suite
never touches the project's real ``logs/audit/`` directory.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_brain.audit.audit_logger import (
    WORKFLOW_OS_OPS,
    WORKFLOW_SECURITY_DEFENSE,
    AuditLogger,
    _sanitize,
    get_default_audit_logger,
    new_workflow_request_id,
    reset_default_audit_logger,
)


class _AuditLoggerTestBase(unittest.TestCase):
    """Common scaffolding: every test gets an isolated tmp directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name) / "audit"
        self.logger = AuditLogger(directory=self.directory, enabled=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# Schema and basic write
# ---------------------------------------------------------------------------


class WriteSchemaTests(_AuditLoggerTestBase):

    def test_write_creates_file_with_full_schema(self) -> None:
        request_id = "ops-abc123def456"
        path = self.logger.write(
            request_id=request_id,
            workflow_type=WORKFLOW_OS_OPS,
            instruction="查看磁盘使用情况",
            agent_decisions={"intent": "DISK_USAGE", "decision": "ALLOW"},
            mcp_trace=[{"server": "os-mcp-server", "tool": "get_disk_usage", "success": True}],
            safety_validation={"decision": "ALLOW", "riskLevel": "LOW"},
            execution_result={"status": "EXECUTED", "exitCode": 0},
            final_status="EXECUTED",
            final_answer="Disk usage normal.",
            extra={"trailLength": 6},
        )
        self.assertIsNotNone(path)
        target = self.directory / f"audit-{request_id}.json"
        self.assertTrue(target.exists(), f"file not created: {target}")
        self.assertEqual(path, str(target))

        with open(target, "r", encoding="utf-8") as f:
            payload = json.load(f)

        # Mandatory schema keys.
        for key in (
            "schemaVersion",
            "writtenAt",
            "requestId",
            "workflowType",
            "instruction",
            "eventId",
            "agentDecisions",
            "mcpTrace",
            "safetyValidation",
            "verification",
            "executionResult",
            "finalStatus",
            "finalAnswer",
            "extra",
        ):
            self.assertIn(key, payload, f"missing key {key}")

        self.assertEqual(payload["schemaVersion"], "1")
        self.assertEqual(payload["requestId"], request_id)
        self.assertEqual(payload["workflowType"], WORKFLOW_OS_OPS)
        self.assertEqual(payload["instruction"], "查看磁盘使用情况")
        self.assertEqual(payload["finalStatus"], "EXECUTED")
        self.assertEqual(payload["finalAnswer"], "Disk usage normal.")
        self.assertEqual(payload["agentDecisions"]["intent"], "DISK_USAGE")
        self.assertEqual(len(payload["mcpTrace"]), 1)
        self.assertEqual(payload["mcpTrace"][0]["tool"], "get_disk_usage")
        self.assertEqual(payload["safetyValidation"]["decision"], "ALLOW")
        self.assertEqual(payload["executionResult"]["status"], "EXECUTED")
        self.assertEqual(payload["extra"], {"trailLength": 6})

    def test_write_filename_pattern(self) -> None:
        path = self.logger.write(
            request_id="wf-deadbeef0001",
            workflow_type=WORKFLOW_SECURITY_DEFENSE,
            event_id="evt-001",
        )
        self.assertIsNotNone(path)
        self.assertTrue(Path(path).name == "audit-wf-deadbeef0001.json")

    def test_write_creates_missing_directory(self) -> None:
        deeper = self.directory / "nested" / "more"
        logger = AuditLogger(directory=deeper, enabled=True)
        self.assertFalse(deeper.exists())
        path = logger.write(
            request_id="ops-1",
            workflow_type=WORKFLOW_OS_OPS,
        )
        self.assertIsNotNone(path)
        self.assertTrue(deeper.exists())

    def test_write_uses_utf8_no_ascii_escape(self) -> None:
        rid = "ops-utf8test"
        self.logger.write(
            request_id=rid,
            workflow_type=WORKFLOW_OS_OPS,
            instruction="检查 8080 端口",
        )
        target = self.directory / f"audit-{rid}.json"
        raw = target.read_text(encoding="utf-8")
        # The raw bytes must NOT contain escaped \u sequences for Chinese.
        self.assertIn("检查 8080 端口", raw)
        self.assertNotIn("\\u68c0", raw)


# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------


class FilenameSafetyTests(_AuditLoggerTestBase):

    def test_unsafe_request_id_is_sanitized(self) -> None:
        path = self.logger.write(
            request_id="../etc/passwd; rm -rf /",
            workflow_type=WORKFLOW_OS_OPS,
        )
        self.assertIsNotNone(path)
        # The actual filename must NOT contain path-traversal characters.
        name = Path(path).name
        self.assertTrue(name.startswith("audit-"))
        self.assertTrue(name.endswith(".json"))
        for forbidden in ("/", "\\", "..", " ", ";"):
            self.assertNotIn(forbidden, name)

    def test_long_request_id_is_truncated(self) -> None:
        rid = "a" * 200
        path = self.logger.write(
            request_id=rid,
            workflow_type=WORKFLOW_OS_OPS,
        )
        self.assertIsNotNone(path)
        # 80-char cap + ``audit-`` prefix + ``.json`` suffix.
        self.assertLessEqual(len(Path(path).name), 80 + len("audit-") + len(".json"))

    def test_empty_request_id_returns_none(self) -> None:
        path = self.logger.write(
            request_id="",
            workflow_type=WORKFLOW_OS_OPS,
        )
        self.assertIsNone(path)


# ---------------------------------------------------------------------------
# Sanitization (secret redaction)
# ---------------------------------------------------------------------------


class SecretRedactionTests(_AuditLoggerTestBase):

    def test_api_key_in_extra_is_redacted_in_file(self) -> None:
        path = self.logger.write(
            request_id="ops-redact1",
            workflow_type=WORKFLOW_OS_OPS,
            extra={
                "AGENT_BRAIN_LLM_API_KEY": "sk-thisis-a-secret-test-key",
                "regular_field": "ok",
            },
        )
        self.assertIsNotNone(path)
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(payload["extra"]["AGENT_BRAIN_LLM_API_KEY"], "***REDACTED***")
        self.assertEqual(payload["extra"]["regular_field"], "ok")

    def test_nested_secret_is_redacted(self) -> None:
        path = self.logger.write(
            request_id="ops-redact2",
            workflow_type=WORKFLOW_OS_OPS,
            agent_decisions={
                "llm": {
                    "api_key": "should-not-leak",
                    "model": "deepseek",
                    "headers": {"Authorization": "Bearer xyz"},
                },
            },
        )
        self.assertIsNotNone(path)
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        decisions = payload["agentDecisions"]
        self.assertEqual(decisions["llm"]["api_key"], "***REDACTED***")
        self.assertEqual(decisions["llm"]["model"], "deepseek")
        self.assertEqual(decisions["llm"]["headers"]["Authorization"], "***REDACTED***")

    def test_redaction_handles_lists_of_dicts(self) -> None:
        path = self.logger.write(
            request_id="ops-redact3",
            workflow_type=WORKFLOW_OS_OPS,
            mcp_trace=[
                {"tool": "x", "secret": "no", "summary": "ok"},
                {"tool": "y", "Token": "no", "summary": "ok"},
            ],
        )
        self.assertIsNotNone(path)
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(payload["mcpTrace"][0]["secret"], "***REDACTED***")
        self.assertEqual(payload["mcpTrace"][1]["Token"], "***REDACTED***")
        # Non-sensitive keys are preserved.
        self.assertEqual(payload["mcpTrace"][0]["summary"], "ok")
        self.assertEqual(payload["mcpTrace"][1]["tool"], "y")

    def test_sanitize_unit_short_circuits_for_scalars(self) -> None:
        # _sanitize is exercised indirectly by every write test; this is
        # a direct sanity check on its scalar pass-through behaviour.
        self.assertEqual(_sanitize("hello"), "hello")
        self.assertEqual(_sanitize(42), 42)
        self.assertEqual(_sanitize(True), True)
        self.assertIsNone(_sanitize(None))
        self.assertEqual(_sanitize((1, "a")), (1, "a"))


# ---------------------------------------------------------------------------
# Failure handling: must NEVER raise
# ---------------------------------------------------------------------------


class FailureHandlingTests(_AuditLoggerTestBase):

    def test_disabled_logger_returns_none_and_writes_nothing(self) -> None:
        disabled = AuditLogger(directory=self.directory, enabled=False)
        path = disabled.write(
            request_id="ops-disabled",
            workflow_type=WORKFLOW_OS_OPS,
            instruction="x",
        )
        self.assertIsNone(path)
        self.assertFalse(any(self.directory.glob("*.json")))

    def test_unknown_workflow_type_skipped_with_warning(self) -> None:
        with self.assertLogs("agent_brain.audit.audit_logger", level="WARNING"):
            path = self.logger.write(
                request_id="ops-bad-workflow",
                workflow_type="not_a_real_workflow",
            )
        self.assertIsNone(path)

    def test_oserror_during_write_is_swallowed(self) -> None:
        # Force ``open()`` to raise; the writer must log a warning and
        # return None instead of bubbling the exception to the caller.
        def _raise(*_args, **_kwargs):
            raise OSError("disk full (simulated)")

        with patch("builtins.open", side_effect=_raise), \
             self.assertLogs("agent_brain.audit.audit_logger", level="WARNING"):
            path = self.logger.write(
                request_id="ops-oserror",
                workflow_type=WORKFLOW_OS_OPS,
                instruction="x",
            )
        self.assertIsNone(path)

    def test_non_serializable_field_uses_default_str(self) -> None:
        # ``object()`` can't be JSON-serialized natively but ``default=str``
        # should coerce it; the writer must still succeed.
        path = self.logger.write(
            request_id="ops-coerce",
            workflow_type=WORKFLOW_OS_OPS,
            extra={"weird": object()},
        )
        self.assertIsNotNone(path)
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIn("weird", payload["extra"])
        self.assertIsInstance(payload["extra"]["weird"], str)


# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------


class EnvironmentConfigTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        # Always reset the singleton between tests.
        reset_default_audit_logger()

    def tearDown(self) -> None:
        self._tmp.cleanup()
        reset_default_audit_logger()

    def test_audit_log_dir_env_overrides_default(self) -> None:
        with patch.dict(os.environ, {"AUDIT_LOG_DIR": self._tmp.name}):
            logger = AuditLogger()
        self.assertEqual(logger.directory, Path(self._tmp.name))

    def test_audit_log_disabled_env_disables_writer(self) -> None:
        with patch.dict(os.environ, {"AUDIT_LOG_DISABLED": "true"}):
            logger = AuditLogger()
        self.assertFalse(logger.enabled)

    def test_singleton_returns_same_instance(self) -> None:
        a = get_default_audit_logger()
        b = get_default_audit_logger()
        self.assertIs(a, b)
        reset_default_audit_logger()
        c = get_default_audit_logger()
        self.assertIsNot(a, c)


# ---------------------------------------------------------------------------
# Workflow request id helper
# ---------------------------------------------------------------------------


class WorkflowRequestIdTests(unittest.TestCase):

    def test_format(self) -> None:
        rid = new_workflow_request_id()
        self.assertTrue(rid.startswith("wf-"))
        self.assertEqual(len(rid), 3 + 12)

    def test_uniqueness_under_concurrency(self) -> None:
        ids: list[str] = []
        lock = threading.Lock()

        def gen() -> None:
            new = new_workflow_request_id()
            with lock:
                ids.append(new)

        threads = [threading.Thread(target=gen) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(ids), 50)
        self.assertEqual(len(set(ids)), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
