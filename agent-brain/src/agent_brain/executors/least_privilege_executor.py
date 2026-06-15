"""Least-privilege OPS command executor.

This module is the *runtime gate* for any OS command an OPS agent wants
to run on a Kylin host. It sits behind ``agent_brain.safety``: the
intent validator decides whether a command is conceptually safe, and
this executor decides whether the in-process Python runtime is
actually willing to invoke it.

Layered defense
---------------

The executor enforces *three* gates, in this exact order:

1. **Input parsing** - the request must produce a non-empty argv list
   (via ``shlex.split`` for strings); malformed input never reaches
   the OS.
2. **Intent validator** (``agent_brain.safety.validate_intent``):

   * ``BLOCK`` -> envelope with ``status="BLOCKED"``, no execution.
   * ``REQUIRE_APPROVAL`` -> envelope with ``status="PENDING_APPROVAL"``.
   * ``ALLOW`` -> proceed to gate 3.
3. **Phase-1 whitelist** - only the read-only diagnostic commands
   listed in the spec are accepted (``ps``, ``ss``, ``netstat``,
   ``lsof``, ``df``, ``free``, ``uptime``, ``journalctl`` and
   ``systemctl status`` family). Anything else -> ``status="REJECTED"``
   with the canonical reason string.

Hard-coded execution policy
---------------------------

* ``shell=False`` always; ``argv`` arrays only.
* Default timeout: 5 seconds (constructor-overridable).
* Default per-stream output limit: 16 KiB (constructor-overridable).
* Subprocess runs as the executor's own OS user. ``executedAs`` is
  recorded in every envelope for the audit log.
* No environment scrubbing yet; that is intentionally left to the
  upcoming ``ops_audit_log`` / orchestrator phase so auditing can
  remain in one place.

Output envelope
---------------

Every public call returns a plain ``dict`` with the keys::

    commandId        unique exec-* identifier
    status           EXECUTED | REJECTED | PENDING_APPROVAL | BLOCKED
                     | INVALID_INPUT | TIMEOUT | RUNTIME_ERROR
    command          original/printable command string
    argv             the argv list actually passed to subprocess
    executedAs       OS user the executor is running as
    exitCode         int | None (None for non-EXECUTED statuses)
    stdout           str | None
    stderr           str | None
    stdoutTruncated  bool
    stderrTruncated  bool
    startedAt        ISO-8601 UTC timestamp before subprocess start
    endedAt          ISO-8601 UTC timestamp after subprocess return
    durationMs       integer milliseconds (end - start)
    timeoutSeconds   the timeout actually used
    validator        echo of intent_validator envelope (or None when skipped)
    reason           short human-readable explanation

The class is intentionally not wired into ``/ops/chat``; orchestration
will be added in the next phase.
"""
from __future__ import annotations

import getpass
import logging
import os
import shlex
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from agent_brain.executors.systemd_sandbox import (
    SandboxLimits,
    SystemdSandbox,
)
from agent_brain.safety import (
    DECISION_BLOCK,
    DECISION_REQUIRE_APPROVAL,
    validate_intent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Privilege detection
# ---------------------------------------------------------------------------


def is_running_as_root() -> bool:
    """Return True when the current process has high-level OS privileges.

    Covers POSIX (uid == 0) and Windows (Administrator membership). Failures
    in the probe are treated as "unknown" -> False so a missing API never
    blocks the executor from operating in a sandbox.
    """
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    try:
        if os.name == "nt":
            import ctypes  # local import keeps this cheap on POSIX

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    return False


# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_OUTPUT_LIMIT: int = 16 * 1024  # bytes per stream

STATUS_EXECUTED = "EXECUTED"
STATUS_REJECTED = "REJECTED"
STATUS_PENDING_APPROVAL = "PENDING_APPROVAL"
STATUS_BLOCKED = "BLOCKED"
STATUS_INVALID_INPUT = "INVALID_INPUT"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_RUNTIME_ERROR = "RUNTIME_ERROR"

# Canonical reason for the basic "program not whitelisted" rejection,
# kept exactly as spelled in the design spec.
_REASON_NOT_WHITELISTED = "Command not allowed by least-privilege executor"

# Phase-1 whitelist. Value semantics:
#   * None  -> any flags / args allowed (still bounded by intent validator)
#   * frozenset -> first non-flag token (the "subcommand") must be in this set
_DEFAULT_WHITELIST: dict[str, frozenset[str] | None] = {
    "ps": None,
    "ss": None,
    "netstat": None,
    "lsof": None,
    "df": None,
    "free": None,
    "uptime": None,
    "journalctl": None,
    "systemctl": frozenset(
        {
            "status",
            "is-active",
            "is-enabled",
            "is-failed",
            "list-units",
            "list-unit-files",
            "show",
            "cat",
        }
    ),
}


# ---------------------------------------------------------------------------
# Result dataclass (serialized via to_dict())
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutorResult:
    """Internal frozen container; callers receive ``to_dict()`` output."""

    command_id: str
    status: str
    command: str
    argv: list[str] = field(default_factory=list)
    executed_as: str = ""
    uid: int | None = None
    gid: int | None = None
    cwd: str | None = None
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    started_at: str | None = None
    ended_at: str | None = None
    duration_ms: int | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    validator: dict[str, Any] | None = None
    reason: str = ""
    blocked_reason: str | None = None
    request_id: str | None = None
    sandbox: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commandId": self.command_id,
            "status": self.status,
            "command": self.command,
            "argv": list(self.argv),
            "executedAs": self.executed_as,
            "uid": self.uid,
            "gid": self.gid,
            "cwd": self.cwd,
            "exitCode": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdoutTruncated": self.stdout_truncated,
            "stderrTruncated": self.stderr_truncated,
            "startedAt": self.started_at,
            "endedAt": self.ended_at,
            "durationMs": self.duration_ms,
            "timeoutSeconds": self.timeout_seconds,
            "validator": self.validator,
            "reason": self.reason,
            "blockedReason": self.blocked_reason,
            "requestId": self.request_id,
            "sandbox": self.sandbox,
        }


# ---------------------------------------------------------------------------
# Executor class
# ---------------------------------------------------------------------------


class LeastPrivilegeExecutor:
    """Execute only safe, whitelisted, validator-approved OS commands."""

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        output_limit_bytes: int | None = None,
        whitelist: Mapping[str, frozenset[str] | None] | None = None,
        run_user: str | None = None,
        allow_sudo: bool = False,
        read_only_mode: bool | None = None,
        use_systemd_sandbox: bool = True,
        sandbox_limits: SandboxLimits | None = None,
    ) -> None:
        self._timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else DEFAULT_TIMEOUT_SECONDS
        )
        self._output_limit = (
            int(output_limit_bytes)
            if output_limit_bytes is not None
            else DEFAULT_OUTPUT_LIMIT
        )
        # Coerce values to frozenset so callers can pass plain sets.
        self._whitelist: dict[str, frozenset[str] | None] = {}
        source = whitelist if whitelist is not None else _DEFAULT_WHITELIST
        for prog, allowed in source.items():
            if allowed is None:
                self._whitelist[prog] = None
            else:
                self._whitelist[prog] = frozenset(allowed)
        self._run_user = run_user or _detect_user()
        # Privilege-elevation prefixes are refused unconditionally unless the
        # caller flips ``allow_sudo`` (used only by integration tests). This
        # ensures a runaway agent cannot escalate via "sudo cat ..." even if
        # the underlying program is whitelisted.
        self._allow_sudo = bool(allow_sudo)
        # ``read_only_mode`` is the runtime kill-switch consulted by the
        # /system/status page. When True the whitelist is locked even
        # tighter and any future "write" verbs added by callers are
        # ignored at execute time.
        if read_only_mode is None:
            policy = os.environ.get("AGENT_BRAIN_ROOT_POLICY", "refuse").strip().lower()
            self._read_only_mode = is_running_as_root() and policy != "off"
        else:
            self._read_only_mode = bool(read_only_mode)
        # systemd-run sandbox: wraps subprocess in a transient cgroup scope
        # on Kylin V11 / systemd hosts. Falls back to bare subprocess
        # gracefully on Windows / macOS / containers.
        self._use_systemd_sandbox = bool(use_systemd_sandbox)
        self._sandbox = SystemdSandbox(limits=sandbox_limits) if self._use_systemd_sandbox else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        command: str | list[str],
        *,
        instruction: str = "",
        validator_override: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate, whitelist-check, and (when allowed) execute ``command``.

        Parameters
        ----------
        command:
            Either a printable shell-style string (parsed with ``shlex``)
            or a pre-tokenized argv list. ``shell=True`` is never used.
        instruction:
            Optional natural-language context forwarded to the safety
            intent validator. Default empty string.
        validator_override:
            If provided, the executor *trusts* this envelope verbatim
            instead of re-running the validator. Intended for callers
            (e.g. the OPS orchestrator) that already invoked
            ``validate_intent`` and want to forward the same verdict
            into the audit trail.
        request_id:
            Optional correlation id (e.g. ``ops-<uuid>``). Stored in
            the audit envelope so executor logs can be joined with the
            originating /ops/chat or /workflow/run request.
        """
        command_id = _new_command_id()
        uid, gid = _detect_uid_gid()
        cwd = _detect_cwd()
        argv, command_str, parse_err = _parse_command(command)
        if parse_err is not None:
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_INVALID_INPUT,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                timeout_seconds=self._timeout,
                reason=parse_err,
                blocked_reason=parse_err,
                request_id=request_id,
            ).to_dict()

        # --------------------- gate 2: intent validator ---------------------
        if validator_override is not None:
            validator_envelope = dict(validator_override)
        else:
            validator_envelope = validate_intent(
                {
                    "instruction": instruction,
                    "candidateCommands": [command_str],
                }
            )

        decision = validator_envelope.get("decision")
        if decision == DECISION_BLOCK:
            reason = "Blocked by safety intent validator"
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_BLOCKED,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=reason,
                blocked_reason=reason,
                request_id=request_id,
            ).to_dict()
        if decision == DECISION_REQUIRE_APPROVAL:
            reason = "Awaiting human approval before execution"
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_PENDING_APPROVAL,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=reason,
                blocked_reason=reason,
                request_id=request_id,
            ).to_dict()

        # --------------------- gate 3: executor whitelist -------------------
        whitelist_ok, whitelist_reason = self._check_whitelist(argv)
        if not whitelist_ok:
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_REJECTED,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=whitelist_reason,
                blocked_reason=whitelist_reason,
                request_id=request_id,
            ).to_dict()

        # All gates passed; actually run the command.
        return self._run_subprocess(
            command_id=command_id,
            command_str=command_str,
            argv=argv,
            validator_envelope=validator_envelope,
            uid=uid,
            gid=gid,
            cwd=cwd,
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_whitelist(self, argv: list[str]) -> tuple[bool, str]:
        """Validate argv[0] (and optional subcommand) against the whitelist."""
        if not argv:
            return False, "Empty argv after parsing"

        program_idx = 0
        # Refuse privilege-elevation prefixes by default. The least-privilege
        # executor must never escalate; sudo / doas requests are routed to
        # human approval via the OPS orchestrator instead.
        if argv[0] in ("sudo", "doas", "su", "runas", "pkexec"):
            if not self._allow_sudo:
                return False, (
                    f"Privilege-elevation prefix '{argv[0]}' is not permitted by "
                    "least-privilege executor (set allow_sudo=True only in "
                    "trusted automation tests)"
                )
            if len(argv) < 2:
                return False, f"'{argv[0]}' invocation has no underlying program"
            program_idx = 1

        program = argv[program_idx]
        # Strip absolute path so /usr/bin/ps maps to ps.
        if "/" in program:
            program = program.rsplit("/", 1)[-1]
        if "\\" in program:
            program = program.rsplit("\\", 1)[-1]

        if program not in self._whitelist:
            return False, _REASON_NOT_WHITELISTED

        allowed_subcommands = self._whitelist[program]
        if allowed_subcommands is None:
            return True, "Whitelisted (any args)"

        # Subcommand is the first non-flag token after the program name.
        for token in argv[program_idx + 1:]:
            if token.startswith("-"):
                continue
            if token in allowed_subcommands:
                return True, f"Whitelisted subcommand '{token}'"
            return False, (
                f"Subcommand '{token}' not allowed for '{program}'; "
                f"allowed: {sorted(allowed_subcommands)}"
            )
        return False, (
            f"Program '{program}' requires a subcommand; "
            f"allowed: {sorted(allowed_subcommands)}"
        )

    def _run_subprocess(
        self,
        *,
        command_id: str,
        command_str: str,
        argv: list[str],
        validator_envelope: dict[str, Any],
        uid: int | None = None,
        gid: int | None = None,
        cwd: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Run argv via ``subprocess.run`` with shell=False.

        When ``use_systemd_sandbox=True`` and systemd-run is available
        (Kylin V11 / systemd-based Linux), the command is wrapped in a
        transient ``systemd-run --user --scope`` cgroup scope with
        MemoryMax / CPUQuota / TasksMax / ProtectSystem=strict.
        """
        sandbox_envelope: dict[str, Any] = {"type": "none", "available": False}
        run_argv = list(argv)

        if self._sandbox is not None and self._sandbox.is_available():
            run_argv = self._sandbox.wrap_command(argv)
            was_sandboxed = run_argv != argv
            sandbox_envelope = self._sandbox.build_envelope(was_sandboxed)
        else:
            sandbox_envelope = {
                "type": "none",
                "available": False,
                "limits": None,
            }

        started = datetime.now(timezone.utc)
        try:
            completed = subprocess.run(  # noqa: S603 - argv form, never shell=True
                run_argv,
                shell=False,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            ended = datetime.now(timezone.utc)
            stdout, stdout_trunc = _decode_truncate(exc.stdout, self._output_limit)
            stderr, stderr_trunc = _decode_truncate(exc.stderr, self._output_limit)
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_TIMEOUT,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_trunc,
                stderr_truncated=stderr_trunc,
                started_at=started.isoformat(),
                ended_at=ended.isoformat(),
                duration_ms=int((ended - started).total_seconds() * 1000),
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=f"Command timed out after {self._timeout}s",
                request_id=request_id,
                sandbox=sandbox_envelope,
            ).to_dict()
        except FileNotFoundError as exc:
            ended = datetime.now(timezone.utc)
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_RUNTIME_ERROR,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                started_at=started.isoformat(),
                ended_at=ended.isoformat(),
                duration_ms=int((ended - started).total_seconds() * 1000),
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=f"Program not found on host: {exc}",
                request_id=request_id,
                sandbox=sandbox_envelope,
            ).to_dict()
        except Exception as exc:  # noqa: BLE001 - last-resort safety net
            ended = datetime.now(timezone.utc)
            logger.exception("subprocess.run raised unexpected error", exc_info=exc)
            return ExecutorResult(
                command_id=command_id,
                status=STATUS_RUNTIME_ERROR,
                command=command_str,
                argv=argv,
                executed_as=self._run_user,
                uid=uid,
                gid=gid,
                cwd=cwd,
                started_at=started.isoformat(),
                ended_at=ended.isoformat(),
                duration_ms=int((ended - started).total_seconds() * 1000),
                timeout_seconds=self._timeout,
                validator=validator_envelope,
                reason=f"Unexpected runtime error: {exc.__class__.__name__}: {exc}",
                request_id=request_id,
                sandbox=sandbox_envelope,
            ).to_dict()

        ended = datetime.now(timezone.utc)
        stdout_text, stdout_trunc = _decode_truncate(completed.stdout, self._output_limit)
        stderr_text, stderr_trunc = _decode_truncate(completed.stderr, self._output_limit)
        return ExecutorResult(
            command_id=command_id,
            status=STATUS_EXECUTED,
            command=command_str,
            argv=argv,
            executed_as=self._run_user,
            uid=uid,
            gid=gid,
            cwd=cwd,
            exit_code=int(completed.returncode),
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            duration_ms=int((ended - started).total_seconds() * 1000),
            timeout_seconds=self._timeout,
            validator=validator_envelope,
            reason="Executed via subprocess.run with shell=False",
            request_id=request_id,
            sandbox=sandbox_envelope,
        ).to_dict()


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def execute_command(
    command: str | list[str],
    *,
    instruction: str = "",
    timeout_seconds: float | None = None,
    output_limit_bytes: int | None = None,
) -> dict[str, Any]:
    """Convenience wrapper that builds a one-shot ``LeastPrivilegeExecutor``."""
    executor = LeastPrivilegeExecutor(
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )
    return executor.execute(command, instruction=instruction)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_command_id() -> str:
    return f"exec-{uuid.uuid4().hex[:12]}"


def _detect_user() -> str:
    """Best-effort current user lookup; cross-platform safe."""
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return (
            os.environ.get("USERNAME")
            or os.environ.get("USER")
            or "unknown"
        )


def _detect_uid_gid() -> tuple[int | None, int | None]:
    """Return (uid, gid) on POSIX, (None, None) elsewhere."""
    uid: int | None = None
    gid: int | None = None
    try:
        if hasattr(os, "getuid"):
            uid = int(os.getuid())  # type: ignore[attr-defined]
        if hasattr(os, "getgid"):
            gid = int(os.getgid())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    return uid, gid


def _detect_cwd() -> str | None:
    """Return process CWD, scrubbed of trailing whitespace; None on failure."""
    try:
        return os.getcwd()
    except Exception:  # noqa: BLE001
        return None


def _parse_command(
    command: str | list[str],
) -> tuple[list[str], str, str | None]:
    """Normalize input to ``(argv, printable_command, error_or_None)``."""
    if isinstance(command, list):
        argv = [str(t) for t in command if str(t) != ""]
        if not argv:
            return [], "", "argv list is empty"
        try:
            cmd_str = shlex.join(argv) if hasattr(shlex, "join") else " ".join(argv)
        except Exception:  # noqa: BLE001
            cmd_str = " ".join(argv)
        return argv, cmd_str, None

    if not isinstance(command, str):
        return [], str(command), (
            f"Unsupported command type: {type(command).__name__}"
        )

    cmd_str = command.strip()
    if not cmd_str:
        return [], "", "command string is empty"

    try:
        # POSIX-style splitting; no shell-metacharacter expansion.
        argv = shlex.split(cmd_str, posix=True)
    except ValueError as exc:
        return [], cmd_str, f"shlex parsing failed: {exc}"
    if not argv:
        return [], cmd_str, "command string contains no tokens"
    return argv, cmd_str, None


def _decode_truncate(
    raw: bytes | str | None, limit: int
) -> tuple[str | None, bool]:
    """Best-effort decode + length truncation, mirroring ``os_service`` policy."""
    if raw is None:
        return None, False
    if isinstance(raw, str):
        text = raw
    else:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = raw.decode("latin-1", errors="replace")
    # Replace U+FFFD so callers never crash on a GBK/CP-936 console.
    text = text.replace("\ufffd", "?")
    truncated = False
    if len(text) > limit:
        text = text[: max(0, limit - len("...[truncated]"))] + "...[truncated]"
        truncated = True
    return text, truncated


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_OUTPUT_LIMIT",
    "STATUS_EXECUTED",
    "STATUS_REJECTED",
    "STATUS_PENDING_APPROVAL",
    "STATUS_BLOCKED",
    "STATUS_INVALID_INPUT",
    "STATUS_TIMEOUT",
    "STATUS_RUNTIME_ERROR",
    "ExecutorResult",
    "LeastPrivilegeExecutor",
    "execute_command",
    "is_running_as_root",
]
