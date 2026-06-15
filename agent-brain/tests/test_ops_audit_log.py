"""Unit tests for ``agent_brain.audit.ops_audit_log``.

Run from ``autonomous-defense-system/agent-brain``::

    pytest -q tests/test_ops_audit_log.py

Tests are grouped one ``TestCase`` per behaviour; each instance writes
to its own ``TemporaryDirectory`` so the suite never touches the
default repo path.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from agent_brain.audit.ops_audit_log import (
    STAGE_BLOCKED,
    STAGE_COMPLETED,
    STAGE_ERROR,
    STAGE_EXECUTED,
    STAGE_INVALID_INPUT,
    STAGE_PENDING_APPROVAL,
    STAGE_REJECTED,
    STAGE_REQUEST_RECEIVED,
    STAGE_RUNTIME_ERROR,
    STAGE_TIMEOUT,
    STAGE_VALIDATED,
    OpsAuditLog,
    new_request_id,
    stage_from_executor_envelope,
    stage_from_validator_envelope,
)


class _AuditTestBase(unittest.TestCase):
    """Common scaffolding: every test gets an isolated tmp file."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "audit.jsonl"
        self.audit = OpsAuditLog(path=self.path, enabled=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# Append + query
# ---------------------------------------------------------------------------


class AppendAndQueryTests(_AuditTestBase):

    def test_append_writes_one_jsonl_line(self) -> None:
        rid = new_request_id()
        result = self.audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            rid,
            instruction="hello",
            candidate_commands=["df -h"],
        )
        self.assertEqual(result["stage"], STAGE_REQUEST_RECEIVED)
        self.assertEqual(result["requestId"], rid)
        self.assertIn("timestamp", result)

        with open(self.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual(event["stage"], STAGE_REQUEST_RECEIVED)
        self.assertEqual(event["instruction"], "hello")
        self.assertEqual(event["candidateCommands"], ["df -h"])

    def test_query_by_request_returns_in_order(self) -> None:
        rid = new_request_id()
        self.audit.append_stage(STAGE_REQUEST_RECEIVED, rid)
        self.audit.append_stage(STAGE_VALIDATED, rid, validator={"decision": "ALLOW"})
        self.audit.append_stage(
            STAGE_EXECUTED, rid, executor={"commandId": "exec-1", "status": "EXECUTED"}
        )
        events = self.audit.query_by_request(rid)
        self.assertEqual(
            [e["stage"] for e in events],
            [STAGE_REQUEST_RECEIVED, STAGE_VALIDATED, STAGE_EXECUTED],
        )

    def test_query_by_request_isolates_other_requests(self) -> None:
        rid1 = new_request_id()
        rid2 = new_request_id()
        self.audit.append_stage(STAGE_REQUEST_RECEIVED, rid1)
        self.audit.append_stage(STAGE_REQUEST_RECEIVED, rid2)
        self.audit.append_stage(STAGE_EXECUTED, rid1)
        events = self.audit.query_by_request(rid1)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["requestId"] == rid1 for e in events))

    def test_query_by_command_filters_via_executor(self) -> None:
        rid = new_request_id()
        self.audit.append_stage(STAGE_REQUEST_RECEIVED, rid)
        self.audit.append_stage(
            STAGE_EXECUTED,
            rid,
            executor={"commandId": "exec-abc", "status": "EXECUTED"},
        )
        events = self.audit.query_by_command("exec-abc")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["executor"]["commandId"], "exec-abc")

    def test_list_recent_returns_last_n(self) -> None:
        rid = new_request_id()
        for i in range(5):
            self.audit.append_stage(
                STAGE_REQUEST_RECEIVED, rid, metadata={"i": i}
            )
        recent = self.audit.list_recent(limit=2)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]["metadata"]["i"], 3)
        self.assertEqual(recent[1]["metadata"]["i"], 4)


# ---------------------------------------------------------------------------
# Replay aggregation
# ---------------------------------------------------------------------------


class ReplayTests(_AuditTestBase):

    def test_replay_aggregates_lifecycle(self) -> None:
        rid = new_request_id()
        self.audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            rid,
            instruction="show disk",
            candidate_commands=["df -h"],
        )
        self.audit.append_stage(
            STAGE_VALIDATED,
            rid,
            validator={"decision": "ALLOW", "riskLevel": "LOW"},
        )
        self.audit.append_stage(
            STAGE_EXECUTED,
            rid,
            executor={"commandId": "exec-1", "status": "EXECUTED", "exitCode": 0},
        )
        self.audit.append_stage(STAGE_COMPLETED, rid, reason="ok")

        snapshot = self.audit.replay(rid)
        self.assertTrue(snapshot["found"])
        self.assertEqual(snapshot["currentStage"], STAGE_COMPLETED)
        self.assertEqual(snapshot["instruction"], "show disk")
        self.assertEqual(snapshot["candidateCommands"], ["df -h"])
        self.assertEqual(snapshot["validator"]["decision"], "ALLOW")
        self.assertEqual(snapshot["executor"]["commandId"], "exec-1")
        self.assertEqual(len(snapshot["events"]), 4)
        self.assertIsNotNone(snapshot["createdAt"])
        self.assertIsNotNone(snapshot["lastUpdatedAt"])

    def test_replay_missing_request_marks_not_found(self) -> None:
        snapshot = self.audit.replay("ops-doesnotexist")
        self.assertFalse(snapshot["found"])
        self.assertEqual(snapshot["events"], [])
        self.assertIsNone(snapshot["currentStage"])
        self.assertIsNone(snapshot["validator"])
        self.assertIsNone(snapshot["executor"])


# ---------------------------------------------------------------------------
# Stage helpers (validator / executor envelope -> stage)
# ---------------------------------------------------------------------------


class StageHelperTests(unittest.TestCase):

    def test_stage_from_validator_decisions(self) -> None:
        self.assertEqual(
            stage_from_validator_envelope({"decision": "ALLOW"}),
            STAGE_VALIDATED,
        )
        self.assertEqual(
            stage_from_validator_envelope({"decision": "BLOCK"}),
            STAGE_BLOCKED,
        )
        self.assertEqual(
            stage_from_validator_envelope({"decision": "REQUIRE_APPROVAL"}),
            STAGE_PENDING_APPROVAL,
        )

    def test_stage_from_executor_status_mapping(self) -> None:
        cases = {
            "EXECUTED": STAGE_EXECUTED,
            "REJECTED": STAGE_REJECTED,
            "BLOCKED": STAGE_BLOCKED,
            "PENDING_APPROVAL": STAGE_PENDING_APPROVAL,
            "INVALID_INPUT": STAGE_INVALID_INPUT,
            "TIMEOUT": STAGE_TIMEOUT,
            "RUNTIME_ERROR": STAGE_RUNTIME_ERROR,
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                self.assertEqual(
                    stage_from_executor_envelope({"status": status}), expected
                )

    def test_stage_from_none_envelope_is_error(self) -> None:
        self.assertEqual(stage_from_validator_envelope(None), STAGE_ERROR)
        self.assertEqual(stage_from_executor_envelope(None), STAGE_ERROR)

    def test_unknown_decision_or_status_is_error(self) -> None:
        self.assertEqual(
            stage_from_validator_envelope({"decision": "XYZ"}), STAGE_ERROR
        )
        self.assertEqual(
            stage_from_executor_envelope({"status": "WHATEVER"}), STAGE_ERROR
        )


# ---------------------------------------------------------------------------
# Disabled log behaviour
# ---------------------------------------------------------------------------


class DisabledLogTests(unittest.TestCase):

    def test_disabled_log_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = OpsAuditLog(path=path, enabled=False)
            result = audit.append_stage(STAGE_REQUEST_RECEIVED, "ops-abc")
            self.assertEqual(result["stage"], STAGE_REQUEST_RECEIVED)
            self.assertFalse(path.exists())
            self.assertEqual(audit.query_by_request("ops-abc"), [])
            self.assertEqual(audit.list_recent(), [])
            self.assertFalse(audit.replay("ops-abc")["found"])


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class ConcurrencyTests(_AuditTestBase):

    def test_threadsafe_appends_produce_valid_jsonl(self) -> None:
        rid = new_request_id()
        n_threads = 8
        n_per_thread = 25

        def worker() -> None:
            for i in range(n_per_thread):
                self.audit.append_stage(
                    STAGE_REQUEST_RECEIVED, rid, metadata={"i": i}
                )

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        events = self.audit.query_by_request(rid)
        self.assertEqual(len(events), n_threads * n_per_thread)
        # Every line in the file must be valid JSON, i.e. no interleaving
        # corruption from concurrent writes.
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                json.loads(stripped)


# ---------------------------------------------------------------------------
# Robustness: malformed lines, raw append, schema coercion
# ---------------------------------------------------------------------------


class MalformedLineTests(_AuditTestBase):

    def test_malformed_lines_are_skipped(self) -> None:
        rid = new_request_id()
        self.audit.append_stage(STAGE_REQUEST_RECEIVED, rid)
        # Inject hand-crafted garbage between two valid events.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("not a json object\n")
            f.write("\n")
            f.write('"a string but not an object"\n')
        self.audit.append_stage(STAGE_EXECUTED, rid)
        events = self.audit.query_by_request(rid)
        # Two valid events, garbage skipped silently.
        self.assertEqual(len(events), 2)
        self.assertEqual(
            [e["stage"] for e in events],
            [STAGE_REQUEST_RECEIVED, STAGE_EXECUTED],
        )


class RawAppendTests(_AuditTestBase):

    def test_append_raw_event_keeps_custom_fields(self) -> None:
        event = {
            "stage": "EXECUTED",
            "requestId": "ops-x",
            "custom": "field",
        }
        result = self.audit.append(event)
        self.assertEqual(result["stage"], "EXECUTED")
        self.assertEqual(result["custom"], "field")
        self.assertIn("timestamp", result)

    def test_append_invalid_stage_falls_back_to_error(self) -> None:
        result = self.audit.append({"stage": "BOGUS_STAGE", "requestId": "ops-x"})
        self.assertEqual(result["stage"], STAGE_ERROR)

    def test_append_non_dict_raises(self) -> None:
        with self.assertRaises(TypeError):
            self.audit.append("not a dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# UTF-8 / non-ASCII content
# ---------------------------------------------------------------------------


class UTF8ContentTests(_AuditTestBase):

    def test_chinese_instruction_roundtrips(self) -> None:
        rid = new_request_id()
        self.audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            rid,
            instruction="请帮我查看一下磁盘占用",
        )
        events = self.audit.query_by_request(rid)
        self.assertEqual(events[0]["instruction"], "请帮我查看一下磁盘占用")
        # Verify the on-disk encoding is UTF-8 (not escaped).
        with open(self.path, "r", encoding="utf-8") as f:
            raw = f.read()
        self.assertIn("请帮我查看一下磁盘占用", raw)


# ---------------------------------------------------------------------------
# Env-driven configuration
# ---------------------------------------------------------------------------


class EnvOverrideTests(unittest.TestCase):

    def test_env_path_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.jsonl"
            os.environ["OPS_AUDIT_LOG_PATH"] = str(path)
            try:
                audit = OpsAuditLog()
                self.assertEqual(audit.path, path)
                audit.append_stage(STAGE_REQUEST_RECEIVED, "ops-x")
                self.assertTrue(path.exists())
            finally:
                os.environ.pop("OPS_AUDIT_LOG_PATH", None)

    def test_env_disabled_flag(self) -> None:
        os.environ["OPS_AUDIT_LOG_DISABLED"] = "1"
        try:
            audit = OpsAuditLog()
            self.assertFalse(audit.enabled)
        finally:
            os.environ.pop("OPS_AUDIT_LOG_DISABLED", None)


# ---------------------------------------------------------------------------
# End-to-end mini scenario: validator + executor envelope -> audit replay
# ---------------------------------------------------------------------------


class EndToEndSimulationTests(_AuditTestBase):
    """Simulate orchestrator wiring without depending on those modules.

    The orchestrator (next phase) will:
        1. mint a request id
        2. append REQUEST_RECEIVED
        3. call safety.validate_intent -> append derived stage
        4. call executor.execute -> append derived stage
        5. append COMPLETED
    This test does steps 2-5 with hand-rolled envelopes so the audit
    contract is locked in before the orchestrator lands.
    """

    def test_block_short_circuit_lifecycle(self) -> None:
        rid = new_request_id()
        validator_env = {
            "decision": "BLOCK",
            "riskLevel": "CRITICAL",
            "matchedRules": [{"ruleId": "B-001"}],
            "reason": "BLOCKed by 1 rule(s): B-001",
            "safeAlternative": "Restrict rm -rf to a specific subdir",
        }
        self.audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            rid,
            instruction="please run rm -rf /",
            candidate_commands=["rm -rf /"],
        )
        self.audit.append_stage(
            stage_from_validator_envelope(validator_env),
            rid,
            validator=validator_env,
            reason=validator_env["reason"],
        )
        self.audit.append_stage(STAGE_COMPLETED, rid, reason="blocked")

        snapshot = self.audit.replay(rid)
        self.assertTrue(snapshot["found"])
        self.assertEqual(snapshot["currentStage"], STAGE_COMPLETED)
        self.assertEqual(snapshot["validator"]["decision"], "BLOCK")
        self.assertIsNone(snapshot["executor"])  # never executed
        self.assertEqual(
            [e["stage"] for e in snapshot["events"]],
            [STAGE_REQUEST_RECEIVED, STAGE_BLOCKED, STAGE_COMPLETED],
        )

    def test_executed_happy_path_lifecycle(self) -> None:
        rid = new_request_id()
        validator_env = {
            "decision": "ALLOW",
            "riskLevel": "LOW",
            "matchedRules": [{"ruleId": "A-003"}],
            "reason": "ALLOWed by 1 rule(s): A-003",
            "safeAlternative": None,
        }
        executor_env = {
            "commandId": "exec-deadbeef",
            "status": "EXECUTED",
            "command": "df -h",
            "argv": ["df", "-h"],
            "executedAs": "kylin",
            "exitCode": 0,
            "stdout": "Filesystem ...",
            "stderr": "",
            "stdoutTruncated": False,
            "stderrTruncated": False,
            "startedAt": "2026-05-09T08:21:00+00:00",
            "endedAt": "2026-05-09T08:21:00.111+00:00",
            "durationMs": 111,
            "timeoutSeconds": 5.0,
            "validator": validator_env,
            "reason": "Executed via subprocess.run with shell=False",
        }
        self.audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            rid,
            instruction="show me the disk usage",
            candidate_commands=["df -h"],
        )
        self.audit.append_stage(
            stage_from_validator_envelope(validator_env),
            rid,
            validator=validator_env,
        )
        self.audit.append_stage(
            stage_from_executor_envelope(executor_env),
            rid,
            validator=validator_env,
            executor=executor_env,
        )
        self.audit.append_stage(STAGE_COMPLETED, rid)

        snapshot = self.audit.replay(rid)
        self.assertEqual(snapshot["currentStage"], STAGE_COMPLETED)
        self.assertEqual(snapshot["executor"]["commandId"], "exec-deadbeef")
        self.assertEqual(snapshot["executor"]["exitCode"], 0)

        # Cross-reference by command id.
        cmd_events = self.audit.query_by_command("exec-deadbeef")
        self.assertEqual(len(cmd_events), 1)
        self.assertEqual(cmd_events[0]["stage"], STAGE_EXECUTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
