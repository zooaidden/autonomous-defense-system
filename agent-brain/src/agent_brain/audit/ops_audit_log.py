"""Append-only JSONL audit log for OPS request lifecycle.

Why JSONL and not a DB
----------------------

* The OPS audit log is append-only and read mostly for replay.
* Phase 1 doesn't have a long-term storage budget; a single JSONL file
  on disk is small, grep-able, easy to ship to logrotate / SIEM, and
  has zero non-stdlib dependencies.
* Cross-process locking (multi-uvicorn-worker safety) is intentionally
  out of scope. Within a process we use ``threading.Lock`` so the
  default async-uvicorn deployment is safe.

Lifecycle stages
----------------

A single OPS request emits multiple events. Typical happy path::

    REQUEST_RECEIVED  -> orchestrator received the user's NL request
    VALIDATED         -> safety.validate_intent ran (decision=ALLOW)
    EXECUTED          -> least-privilege executor ran the command
    COMPLETED         -> orchestrator finalized the response

Common short-circuits::

    REQUEST_RECEIVED -> BLOCKED            (validator said BLOCK)
    REQUEST_RECEIVED -> PENDING_APPROVAL   (validator said REQUIRE_APPROVAL)
    REQUEST_RECEIVED -> VALIDATED -> REJECTED
                                          (validator ALLOW, executor whitelist no)

The validator decision and executor status both map to canonical
stages via :func:`stage_from_validator_envelope` and
:func:`stage_from_executor_envelope` respectively.

Wire format
-----------

Each line is a UTF-8 JSON object with these keys::

    timestamp           ISO-8601 UTC, injected if missing
    stage               one of STAGE_* constants (see below)
    requestId           "ops-..." identifier (orchestrator-level)
    actor               "system" / "user:<name>"
    instruction         original natural-language string
    candidateCommands   list[str]
    candidateActions    list[dict]
    validator           verbatim validate_intent envelope (or None)
    executor            verbatim least-privilege executor envelope (or None)
    metadata            free-form dict for orchestrator-specific fields
    reason              short human-readable note

Lines that fail to parse on read are skipped (logged at DEBUG) so a
truncated tail can never crash the whole replay.

Public surface
--------------

* :class:`OpsAuditLog` - injectable instance (use this from tests).
* :func:`get_default_audit_log` - process-wide singleton, env-configured.
* :func:`new_request_id` - mint a fresh "ops-XXXXXXXX" identifier.
* ``stage_from_*_envelope`` helpers for orchestrator convenience.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------

STAGE_REQUEST_RECEIVED = "REQUEST_RECEIVED"
STAGE_PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
STAGE_CONFIG_GUARD_BLOCKED = "CONFIG_GUARD_BLOCKED"
STAGE_DANGEROUS_INTENT_DETECTED = "DANGEROUS_INTENT_DETECTED"
STAGE_VALIDATED = "VALIDATED"
STAGE_EXECUTED = "EXECUTED"
STAGE_BLOCKED = "BLOCKED"
STAGE_REJECTED = "REJECTED"
STAGE_PENDING_APPROVAL = "PENDING_APPROVAL"
STAGE_APPROVED = "APPROVED"
STAGE_DENIED = "DENIED"
STAGE_TIMEOUT = "TIMEOUT"
STAGE_INVALID_INPUT = "INVALID_INPUT"
STAGE_RUNTIME_ERROR = "RUNTIME_ERROR"
STAGE_EXECUTION_SKIPPED = "EXECUTION_SKIPPED"
STAGE_COMPLETED = "COMPLETED"
STAGE_ERROR = "ERROR"

_VALID_STAGES = frozenset(
    {
        STAGE_REQUEST_RECEIVED,
        STAGE_PROMPT_INJECTION_DETECTED,
        STAGE_CONFIG_GUARD_BLOCKED,
        STAGE_DANGEROUS_INTENT_DETECTED,
        STAGE_VALIDATED,
        STAGE_EXECUTED,
        STAGE_BLOCKED,
        STAGE_REJECTED,
        STAGE_PENDING_APPROVAL,
        STAGE_APPROVED,
        STAGE_DENIED,
        STAGE_TIMEOUT,
        STAGE_INVALID_INPUT,
        STAGE_RUNTIME_ERROR,
        STAGE_EXECUTION_SKIPPED,
        STAGE_COMPLETED,
        STAGE_ERROR,
    }
)

# Map executor envelope status -> audit stage
_EXECUTOR_STATUS_TO_STAGE: dict[str, str] = {
    "EXECUTED": STAGE_EXECUTED,
    "REJECTED": STAGE_REJECTED,
    "BLOCKED": STAGE_BLOCKED,
    "PENDING_APPROVAL": STAGE_PENDING_APPROVAL,
    "INVALID_INPUT": STAGE_INVALID_INPUT,
    "TIMEOUT": STAGE_TIMEOUT,
    "RUNTIME_ERROR": STAGE_RUNTIME_ERROR,
}

# ---------------------------------------------------------------------------
# Default location and env hooks
# ---------------------------------------------------------------------------

# Path lookup: agent-brain/src/agent_brain/audit/ops_audit_log.py
#   parents[0] -> agent_brain/audit
#   parents[1] -> agent_brain
#   parents[2] -> src
#   parents[3] -> agent-brain
_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[3] / "data"
_DEFAULT_AUDIT_PATH = _DEFAULT_DATA_DIR / "ops_audit.jsonl"

_ENV_PATH = "OPS_AUDIT_LOG_PATH"
_ENV_DISABLED = "OPS_AUDIT_LOG_DISABLED"
_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def new_request_id() -> str:
    """Generate a fresh OPS request id (``ops-`` + 12 hex chars)."""
    return f"ops-{uuid.uuid4().hex[:12]}"


def stage_from_executor_envelope(envelope: dict[str, Any] | None) -> str:
    """Map an executor envelope ``status`` to the canonical audit stage."""
    if not envelope:
        return STAGE_ERROR
    status = str(envelope.get("status", "")).upper()
    return _EXECUTOR_STATUS_TO_STAGE.get(status, STAGE_ERROR)


def stage_from_validator_envelope(envelope: dict[str, Any] | None) -> str:
    """Map a validator envelope ``decision`` to the canonical audit stage."""
    if not envelope:
        return STAGE_ERROR
    decision = str(envelope.get("decision", "")).upper()
    if decision == "BLOCK":
        return STAGE_BLOCKED
    if decision == "REQUIRE_APPROVAL":
        return STAGE_PENDING_APPROVAL
    if decision == "ALLOW":
        return STAGE_VALIDATED
    return STAGE_ERROR


def _now_iso() -> str:
    """Return ISO-8601 UTC timestamp with microsecond resolution."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# OpsAuditLog
# ---------------------------------------------------------------------------


class OpsAuditLog:
    """Append-only JSONL audit log for OPS request lifecycle."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        enabled: bool | None = None,
    ) -> None:
        if enabled is None:
            self._enabled = (
                os.environ.get(_ENV_DISABLED, "").strip().lower() not in _TRUTHY
            )
        else:
            self._enabled = bool(enabled)

        if path is None:
            env_path = os.environ.get(_ENV_PATH, "").strip()
            self._path = Path(env_path) if env_path else _DEFAULT_AUDIT_PATH
        else:
            self._path = Path(path)

        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append a normalized event dict to the JSONL file.

        The event always gets:
          * ``timestamp`` (ISO-8601 UTC) - injected if missing.
          * ``stage`` - coerced to STAGE_ERROR if missing or unknown.

        Returns the normalized event. When the log is disabled this
        returns the normalized event but does NOT touch disk; callers
        can still pass it to other sinks (logger, response body, etc.).
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")

        normalized: dict[str, Any] = dict(event)
        normalized.setdefault("timestamp", _now_iso())
        stage = str(normalized.get("stage", "")).upper()
        normalized["stage"] = stage if stage in _VALID_STAGES else STAGE_ERROR

        if not self._enabled:
            return normalized

        # ``ensure_ascii=False`` keeps Chinese instructions readable in the
        # raw JSONL; ``default=str`` is a last-resort fallback for stray
        # objects (Path, datetime) that may slip into metadata.
        line = json.dumps(normalized, ensure_ascii=False, default=str)
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError as exc:
                logger.warning(
                    "Failed to write OPS audit event to %s: %s", self._path, exc
                )
        return normalized

    def append_stage(
        self,
        stage: str,
        request_id: str,
        *,
        actor: str = "system",
        instruction: str = "",
        candidate_commands: list[str] | None = None,
        candidate_actions: list[dict[str, Any]] | None = None,
        validator: dict[str, Any] | None = None,
        executor: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        """Build a structured event with the canonical schema and append it."""
        event: dict[str, Any] = {
            "stage": stage,
            "requestId": request_id,
            "actor": actor,
            "instruction": instruction,
            "candidateCommands": list(candidate_commands or []),
            "candidateActions": list(candidate_actions or []),
            "validator": validator,
            "executor": executor,
            "metadata": dict(metadata or {}),
            "reason": reason,
        }
        return self.append(event)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def _load_all(self) -> list[dict[str, Any]]:
        """Read the entire log into memory under the write lock.

        Phase 1 logs are expected to stay small (orders of KB-MB). When
        the file grows beyond that, the upgrade path is to introduce a
        rotating sink rather than a streaming reader, since we want to
        keep the read API trivially synchronous for the FastAPI route.
        """
        if not self._enabled:
            return []
        if not self._path.exists():
            return []
        with self._lock:
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    raw_lines = f.readlines()
            except OSError as exc:
                logger.warning("Failed to read OPS audit log %s: %s", self._path, exc)
                return []

        events: list[dict[str, Any]] = []
        for line_num, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug(
                    "OPS audit log %s: skipping malformed line %d",
                    self._path,
                    line_num,
                )
                continue
            if isinstance(obj, dict):
                events.append(obj)
        return events

    def query_by_request(self, request_id: str) -> list[dict[str, Any]]:
        """Return events matching ``requestId`` in append (chronological) order."""
        if not request_id:
            return []
        return [e for e in self._load_all() if e.get("requestId") == request_id]

    def query_by_command(self, command_id: str) -> list[dict[str, Any]]:
        """Return events whose ``executor.commandId`` matches ``command_id``."""
        if not command_id:
            return []
        out: list[dict[str, Any]] = []
        for event in self._load_all():
            executor = event.get("executor")
            if isinstance(executor, dict) and executor.get("commandId") == command_id:
                out.append(event)
        return out

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent ``limit`` events (in append order)."""
        events = self._load_all()
        if limit <= 0:
            return events
        return events[-limit:]

    def replay(self, request_id: str) -> dict[str, Any]:
        """Aggregate every event for ``request_id`` into one snapshot.

        This is the shape ``GET /ops/audit/{id}`` will return. The
        ``found`` flag lets the route distinguish "no such request"
        from "request exists with empty fields".
        """
        events = self.query_by_request(request_id)
        if not events:
            return {
                "requestId": request_id,
                "events": [],
                "currentStage": None,
                "instruction": "",
                "candidateCommands": [],
                "candidateActions": [],
                "validator": None,
                "executor": None,
                "createdAt": None,
                "lastUpdatedAt": None,
                "found": False,
            }

        # Walk events to extract the latest non-empty payload of each
        # interesting field. This handles partial / out-of-order writes
        # gracefully.
        validator: dict[str, Any] | None = None
        executor: dict[str, Any] | None = None
        instruction = ""
        candidate_commands: list[str] = []
        candidate_actions: list[dict[str, Any]] = []
        for event in events:
            v = event.get("validator")
            if isinstance(v, dict) and v:
                validator = v
            e = event.get("executor")
            if isinstance(e, dict) and e:
                executor = e
            if event.get("instruction"):
                instruction = str(event["instruction"])
            if event.get("candidateCommands"):
                candidate_commands = list(event["candidateCommands"])
            if event.get("candidateActions"):
                candidate_actions = list(event["candidateActions"])

        return {
            "requestId": request_id,
            "events": events,
            "currentStage": events[-1].get("stage"),
            "instruction": instruction,
            "candidateCommands": candidate_commands,
            "candidateActions": candidate_actions,
            "validator": validator,
            "executor": executor,
            "createdAt": events[0].get("timestamp"),
            "lastUpdatedAt": events[-1].get("timestamp"),
            "found": True,
        }


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_DEFAULT_LOG: OpsAuditLog | None = None
_DEFAULT_LOG_LOCK = threading.Lock()


def get_default_audit_log() -> OpsAuditLog:
    """Return the lazily-initialized process-wide audit log.

    Configuration is read from the environment exactly once, on first
    access. Tests should call :func:`reset_default_audit_log` between
    runs if they mutate ``OPS_AUDIT_LOG_PATH`` or ``OPS_AUDIT_LOG_DISABLED``.
    """
    global _DEFAULT_LOG
    if _DEFAULT_LOG is None:
        with _DEFAULT_LOG_LOCK:
            if _DEFAULT_LOG is None:
                _DEFAULT_LOG = OpsAuditLog()
    return _DEFAULT_LOG


def reset_default_audit_log() -> None:
    """Drop the cached singleton (test hook)."""
    global _DEFAULT_LOG
    with _DEFAULT_LOG_LOCK:
        _DEFAULT_LOG = None


__all__ = [
    "STAGE_REQUEST_RECEIVED",
    "STAGE_PROMPT_INJECTION_DETECTED",
    "STAGE_CONFIG_GUARD_BLOCKED",
    "STAGE_DANGEROUS_INTENT_DETECTED",
    "STAGE_VALIDATED",
    "STAGE_EXECUTED",
    "STAGE_BLOCKED",
    "STAGE_REJECTED",
    "STAGE_PENDING_APPROVAL",
    "STAGE_APPROVED",
    "STAGE_DENIED",
    "STAGE_TIMEOUT",
    "STAGE_INVALID_INPUT",
    "STAGE_RUNTIME_ERROR",
    "STAGE_EXECUTION_SKIPPED",
    "STAGE_COMPLETED",
    "STAGE_ERROR",
    "OpsAuditLog",
    "new_request_id",
    "stage_from_executor_envelope",
    "stage_from_validator_envelope",
    "get_default_audit_log",
    "reset_default_audit_log",
]
