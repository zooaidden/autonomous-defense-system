"""Unit tests for ``agent_brain.executors.least_privilege_executor``.

Run from ``autonomous-defense-system/agent-brain``::

    pytest -q tests/test_least_privilege_executor.py

Test coverage matches the spec:

* whitelisted reads (``df -h``, ``ps aux``, ``systemctl status sshd``)
  hit ``subprocess.run`` and return EXECUTED;
* ``rm -rf /`` is BLOCKED by the safety validator before any exec;
* ``systemctl restart nginx`` returns PENDING_APPROVAL;
* commands the validator allows but the executor whitelist refuses
  (e.g. ``whoami``) return REJECTED with the canonical reason;
* malformed input returns INVALID_INPUT;
* timeout / output-limit / argv-list paths produce the expected envelope.

``subprocess.run`` is mocked everywhere so the suite is fully
deterministic and runs identically on Linux and Windows hosts.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from agent_brain.executors.least_privilege_executor import (
    DEFAULT_TIMEOUT_SECONDS,
    STATUS_BLOCKED,
    STATUS_EXECUTED,
    STATUS_INVALID_INPUT,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    STATUS_TIMEOUT,
    LeastPrivilegeExecutor,
    execute_command,
)


class _FakeCompleted:
    """Stand-in for ``subprocess.CompletedProcess`` in tests."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Whitelisted reads -> EXECUTED
# ---------------------------------------------------------------------------


class WhitelistedExecutionTests(unittest.TestCase):

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_df_h_executes(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(
            0,
            b"Filesystem  Size  Used  Avail\n/dev/sda1   100G  50G   50G\n",
            b"",
        )
        env = execute_command("df -h")
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["exitCode"], 0)
        self.assertIn("/dev/sda1", env["stdout"])
        self.assertEqual(env["argv"], ["df", "-h"])
        self.assertEqual(env["timeoutSeconds"], DEFAULT_TIMEOUT_SECONDS)
        self.assertIsNotNone(env["startedAt"])
        self.assertIsNotNone(env["endedAt"])
        self.assertGreaterEqual(env["durationMs"], 0)
        self.assertTrue(env["commandId"].startswith("exec-"))
        self.assertTrue(env["executedAs"])
        self.assertEqual(env["validator"]["decision"], "ALLOW")
        # Sanity: shell=False and argv form (no shell metacharacter expansion).
        call_args = mock_run.call_args
        self.assertEqual(call_args.args[0], ["df", "-h"])
        self.assertFalse(call_args.kwargs.get("shell", True))

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_ps_aux_executes(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(
            0,
            b"USER   PID  CMD\nroot     1  init\n",
            b"",
        )
        env = execute_command("ps aux")
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["argv"], ["ps", "aux"])
        self.assertEqual(env["exitCode"], 0)
        self.assertIn("PID", env["stdout"])
        self.assertEqual(env["validator"]["decision"], "ALLOW")

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_systemctl_status_executes(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(
            0, b"Active: active (running)\n", b""
        )
        env = execute_command("systemctl status sshd")
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["argv"], ["systemctl", "status", "sshd"])

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_journalctl_n_executes(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"-- Logs begin at --\n", b"")
        env = execute_command("journalctl -n 100")
        self.assertEqual(env["status"], STATUS_EXECUTED, env)


# ---------------------------------------------------------------------------
# Validator gate: BLOCKED / PENDING_APPROVAL
# ---------------------------------------------------------------------------


class ValidatorGateTests(unittest.TestCase):

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_rm_rf_root_is_blocked(self, mock_run) -> None:
        env = execute_command("rm -rf /")
        self.assertEqual(env["status"], STATUS_BLOCKED, env)
        self.assertIsNone(env["exitCode"])
        self.assertIsNone(env["stdout"])
        self.assertIsNone(env["stderr"])
        self.assertEqual(env["validator"]["decision"], "BLOCK")
        # Must never reach subprocess.
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_systemctl_restart_pending_approval(self, mock_run) -> None:
        env = execute_command("systemctl restart nginx")
        self.assertEqual(env["status"], STATUS_PENDING_APPROVAL, env)
        self.assertIsNone(env["exitCode"])
        self.assertEqual(env["validator"]["decision"], "REQUIRE_APPROVAL")
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_kill_9_pending_approval(self, mock_run) -> None:
        env = execute_command("kill -9 1234")
        self.assertEqual(env["status"], STATUS_PENDING_APPROVAL, env)
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_validator_override_is_honored(self, mock_run) -> None:
        # Caller supplied an explicit BLOCK envelope; executor must trust it
        # without re-invoking the in-process validator.
        executor = LeastPrivilegeExecutor()
        env = executor.execute(
            "df -h",
            validator_override={
                "decision": "BLOCK",
                "riskLevel": "CRITICAL",
                "matchedRules": [],
                "reason": "external override",
                "safeAlternative": None,
            },
        )
        self.assertEqual(env["status"], STATUS_BLOCKED)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Whitelist gate: validator says ALLOW but the executor still refuses
# ---------------------------------------------------------------------------


class WhitelistGateTests(unittest.TestCase):

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_whoami_is_rejected_even_though_validator_allows(self, mock_run) -> None:
        # ``whoami`` is ALLOWed by intent_validator (rule A-011) but is
        # NOT in the Phase-1 executor whitelist.
        env = execute_command("whoami")
        self.assertEqual(env["status"], STATUS_REJECTED, env)
        self.assertEqual(env["validator"]["decision"], "ALLOW")
        self.assertEqual(
            env["reason"], "Command not allowed by least-privilege executor"
        )
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_unknown_command_routes_to_pending_approval(self, mock_run) -> None:
        # Unknown commands fall to the validator's conservative default
        # (REQUIRE_APPROVAL), so the executor never reaches the whitelist.
        env = execute_command("mysql -u root -e 'select 1'")
        self.assertEqual(env["status"], STATUS_PENDING_APPROVAL, env)
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_systemctl_with_disallowed_subcommand_is_rejected(self, mock_run) -> None:
        # ``systemctl daemon-reload`` is not a Phase-1 read-only subcommand.
        # Validator says no rule matches -> default REQUIRE_APPROVAL, so the
        # executor short-circuits before touching the whitelist. Test the
        # whitelist branch directly via a forged ALLOW override.
        executor = LeastPrivilegeExecutor()
        env = executor.execute(
            "systemctl daemon-reload",
            validator_override={
                "decision": "ALLOW",
                "riskLevel": "LOW",
                "matchedRules": [],
                "reason": "forged for test",
                "safeAlternative": None,
            },
        )
        self.assertEqual(env["status"], STATUS_REJECTED, env)
        self.assertIn("daemon-reload", env["reason"])
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_sudo_prefix_is_rejected_by_default(self, mock_run) -> None:
        # Privilege-elevation prefixes must be refused even when the wrapped
        # program is whitelisted. This is the contract that keeps a runaway
        # agent from escalating via "sudo cat /etc/shadow".
        env = execute_command("sudo ps -ef")
        self.assertEqual(env["status"], STATUS_REJECTED, env)
        self.assertIn("Privilege-elevation prefix 'sudo'", env["reason"])
        mock_run.assert_not_called()

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_sudo_prefix_accepted_when_explicit_opt_in(self, mock_run) -> None:
        # Trusted automation tests can flip ``allow_sudo`` to verify the
        # underlying-program check still works. This is the only way to get
        # past the privilege-elevation gate.
        from agent_brain.executors.least_privilege_executor import LeastPrivilegeExecutor

        mock_run.return_value = _FakeCompleted(0, b"USER PID CMD\n", b"")
        executor = LeastPrivilegeExecutor(allow_sudo=True)
        env = executor.execute(
            "sudo ps -ef",
            validator_override={
                "decision": "ALLOW",
                "riskLevel": "LOW",
                "matchedRules": [],
                "reason": "forged for test",
                "safeAlternative": None,
            },
        )
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["argv"], ["sudo", "ps", "-ef"])

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_absolute_path_is_normalized_via_basename(self, mock_run) -> None:
        # The intent validator's ALLOW patterns are anchored to bare
        # program names (``^\s*ps\b``); an absolute path does not match
        # and the validator falls back to REQUIRE_APPROVAL. This test
        # specifically exercises the executor's whitelist basename logic
        # by forging an ALLOW envelope, simulating what an upstream
        # orchestrator would do after its own validation step.
        mock_run.return_value = _FakeCompleted(0, b"USER PID CMD\n", b"")
        executor = LeastPrivilegeExecutor()
        env = executor.execute(
            "/usr/bin/ps -ef",
            validator_override={
                "decision": "ALLOW",
                "riskLevel": "LOW",
                "matchedRules": [],
                "reason": "forged for test",
                "safeAlternative": None,
            },
        )
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["argv"], ["/usr/bin/ps", "-ef"])


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


class InvalidInputTests(unittest.TestCase):

    def test_empty_string_is_invalid(self) -> None:
        env = execute_command("")
        self.assertEqual(env["status"], STATUS_INVALID_INPUT, env)

    def test_empty_argv_list_is_invalid(self) -> None:
        env = execute_command([])
        self.assertEqual(env["status"], STATUS_INVALID_INPUT, env)

    def test_unbalanced_quotes_invalid(self) -> None:
        env = execute_command("ps 'aux")
        self.assertEqual(env["status"], STATUS_INVALID_INPUT, env)
        self.assertIn("shlex", env["reason"].lower())


# ---------------------------------------------------------------------------
# Subprocess error paths
# ---------------------------------------------------------------------------


class SubprocessErrorTests(unittest.TestCase):

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_timeout_is_reported(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["ps", "aux"], timeout=5.0
        )
        env = execute_command("ps aux", timeout_seconds=5.0)
        self.assertEqual(env["status"], STATUS_TIMEOUT, env)
        self.assertIn("timed out", env["reason"].lower())
        self.assertEqual(env["timeoutSeconds"], 5.0)

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_long_stdout_is_truncated(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"x" * 50_000, b"")
        env = execute_command("ps aux", output_limit_bytes=1024)
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertTrue(env["stdoutTruncated"])
        self.assertLessEqual(len(env["stdout"]), 1024)
        self.assertIn("[truncated]", env["stdout"])


# ---------------------------------------------------------------------------
# argv list input
# ---------------------------------------------------------------------------


class ArgvListInputTests(unittest.TestCase):

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_argv_list_is_accepted(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"", b"")
        env = execute_command(["ps", "-ef"])
        self.assertEqual(env["status"], STATUS_EXECUTED, env)
        self.assertEqual(env["argv"], ["ps", "-ef"])
        # subprocess must have received the argv array verbatim.
        call_args = mock_run.call_args
        self.assertEqual(call_args.args[0], ["ps", "-ef"])


# ---------------------------------------------------------------------------
# Output envelope shape
# ---------------------------------------------------------------------------


class EnvelopeShapeTests(unittest.TestCase):

    REQUIRED_KEYS = {
        "commandId",
        "status",
        "command",
        "argv",
        "executedAs",
        "uid",
        "gid",
        "cwd",
        "exitCode",
        "stdout",
        "stderr",
        "stdoutTruncated",
        "stderrTruncated",
        "startedAt",
        "endedAt",
        "durationMs",
        "timeoutSeconds",
        "validator",
        "reason",
        "blockedReason",
        "requestId",
    }

    def test_envelope_keys_for_blocked(self) -> None:
        env = execute_command("rm -rf /")
        self.assertEqual(set(env.keys()), self.REQUIRED_KEYS, env.keys())

    @patch("agent_brain.executors.least_privilege_executor.subprocess.run")
    def test_envelope_keys_for_executed(self, mock_run) -> None:
        mock_run.return_value = _FakeCompleted(0, b"", b"")
        env = execute_command("df -h")
        self.assertEqual(set(env.keys()), self.REQUIRED_KEYS, env.keys())


if __name__ == "__main__":
    unittest.main(verbosity=2)
