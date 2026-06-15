"""Per-request JSON audit-file writer.

This module sits **alongside** ``ops_audit_log`` (which writes incremental
JSONL events for OPS request replay). Where ``OpsAuditLog`` is an
append-only event stream, ``AuditLogger`` writes ONE consolidated JSON
file per request so that:

* SIEM / forensic tools can ingest a single self-contained snapshot.
* ``GET /ops/chat`` and ``POST /workflow/run`` can return a stable
  ``auditFile`` field pointing at the snapshot on disk.

Both sinks are best-effort: a write failure here MUST NOT disrupt the
caller's main flow. Failures are logged at WARNING and the writer
returns ``None``; callers should treat that as "no auditFile field".

Schema (v1)
-----------

A single audit file is a JSON object with the following keys::

    schemaVersion       "1"
    writtenAt           ISO-8601 UTC timestamp of when this file was flushed
    requestId           short stable id (ops-XXXXXXXX or wf-XXXXXXXX)
    workflowType        "os_ops" | "security_defense"
    instruction         original natural-language instruction (OPS only)
    eventId             SecurityEvent id (security-defense only)
    agentDecisions      free-form dict of multi-agent / coordinator outputs
    mcpTrace            list of MCP tool call envelopes
    safetyValidation    intent-validator envelope (OPS) or policy-validation
                        envelope (security-defense)
    verification        formal-verifier envelope (security-defense only)
    executionResult     least-privilege-executor or actuator-service envelope
    finalStatus         normalized terminal state (e.g. EXECUTED, BLOCKED,
                        PENDING_APPROVAL, ENTER_VERIFICATION, ...)
    finalAnswer         human-readable final answer (OPS only)
    extra               caller-supplied free-form dict for forward-compat

Sensitive keys (api_key, secret, password, token, authorization, bearer)
are recursively redacted with ``***REDACTED***`` before flushing to disk
so an LLM key that accidentally lands in a payload never reaches the
audit directory.

Defaults
--------

* Output directory: ``<repo_root>/logs/audit/`` where ``<repo_root>`` is
  resolved as ``Path(__file__).parents[4]``, i.e. ``autonomous-defense-system/``.
  This matches the spec hint
  ``D:\\multiple-agent\\autonomous-defense-system\\logs\\audit``.
* Filename: ``audit-<request_id>.json`` with ``request_id`` sanitized to
  filesystem-safe characters (``[A-Za-z0-9._-]``) and capped at 80 chars.
* Env override: ``AUDIT_LOG_DIR`` (path), ``AUDIT_LOG_DISABLED`` (truthy).

Public surface
--------------

* :class:`AuditLogger` - injectable instance (use this from tests).
* :func:`get_default_audit_logger` - process-wide singleton.
* :func:`reset_default_audit_logger` - test hook.
* :data:`WORKFLOW_OS_OPS` / :data:`WORKFLOW_SECURITY_DEFENSE` - canonical
  ``workflowType`` constants.
* :func:`new_workflow_request_id` - mint a fresh ``wf-XXXXXXXX`` id for
  ``/workflow/run`` (kept here so callers don't have to copy the format).
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

WORKFLOW_OS_OPS = "os_ops"
WORKFLOW_SECURITY_DEFENSE = "security_defense"

_VALID_WORKFLOW_TYPES = frozenset({WORKFLOW_OS_OPS, WORKFLOW_SECURITY_DEFENSE})


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
#
# audit_logger.py lives at:
#   autonomous-defense-system/agent-brain/src/agent_brain/audit/audit_logger.py
#   parents[0] -> agent_brain/audit
#   parents[1] -> agent_brain
#   parents[2] -> src
#   parents[3] -> agent-brain
#   parents[4] -> autonomous-defense-system   <-- repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_AUDIT_DIR = _REPO_ROOT / "logs" / "audit"

_ENV_DIR = "AUDIT_LOG_DIR"
_ENV_DISABLED = "AUDIT_LOG_DISABLED"
_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------

# Match dict keys that are commonly used to carry secrets. We only inspect
# key NAMES (not values), so we never have to fingerprint or guess at
# whether a string "looks like" a key.
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[\-_]?key|access[\-_]?key|secret|passwd|password|"
    r"token|authorization|bearer|credential)",
    re.IGNORECASE,
)
_REDACTED = "***REDACTED***"


def _sanitize(value: Any) -> Any:
    """Return a deep copy of ``value`` with secret-bearing keys redacted.

    Walks ``dict`` / ``list`` / ``tuple`` recursively. Strings, numbers,
    booleans, ``None`` and unknown types are returned as-is.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            if _SENSITIVE_KEY_RE.search(key_str):
                out[key_str] = _REDACTED
            else:
                out[key_str] = _sanitize(v)
        return out
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize(item) for item in value)
    return value


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

# Filename-safe character class: alphanumerics plus underscore and hyphen.
# We deliberately exclude '.' here so a malicious request_id like
# "../etc/passwd" can't survive sanitization as "..-etc-passwd" and still
# carry the '..' segment that path utilities treat as parent traversal.
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_\-]")
_MAX_REQUEST_ID_LEN = 80


def _safe_filename_part(text: str) -> str:
    """Coerce ``text`` to a filesystem-safe identifier (cap at 80 chars).

    Any character outside ``[A-Za-z0-9_-]`` is replaced with a single
    hyphen and runs of hyphens are collapsed so the result stays
    readable. The output is never empty (returns ``"unknown"`` instead).
    """
    if not text:
        return "unknown"
    cleaned = _FILENAME_SAFE_RE.sub("-", text)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    cleaned = cleaned[:_MAX_REQUEST_ID_LEN]
    return cleaned or "unknown"


def new_workflow_request_id() -> str:
    """Mint a fresh ``wf-XXXXXXXX`` id for ``/workflow/run`` audit files."""
    return f"wf-{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Write one consolidated JSON audit file per request.

    Thread-safe within a process via an internal ``threading.Lock``;
    cross-process safety is intentionally out of scope for Phase 1 (use
    one process per audit dir, or override ``AUDIT_LOG_DIR`` per worker).
    """

    SCHEMA_VERSION = "1"

    def __init__(
        self,
        directory: Path | str | None = None,
        *,
        enabled: bool | None = None,
    ) -> None:
        if enabled is None:
            self._enabled = (
                os.environ.get(_ENV_DISABLED, "").strip().lower() not in _TRUTHY
            )
        else:
            self._enabled = bool(enabled)

        if directory is None:
            env_dir = os.environ.get(_ENV_DIR, "").strip()
            self._directory = Path(env_dir) if env_dir else _DEFAULT_AUDIT_DIR
        else:
            self._directory = Path(directory)

        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def enabled(self) -> bool:
        return self._enabled

    def file_path(self, request_id: str) -> Path:
        """Return the absolute path where ``request_id`` would be written."""
        safe = _safe_filename_part(request_id)
        return self._directory / f"audit-{safe}.json"

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def write(
        self,
        *,
        request_id: str,
        workflow_type: str,
        instruction: str | None = None,
        event_id: str | None = None,
        agent_decisions: dict[str, Any] | None = None,
        mcp_trace: Iterable[dict[str, Any]] | None = None,
        safety_validation: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
        execution_result: dict[str, Any] | None = None,
        final_status: str = "UNKNOWN",
        final_answer: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str | None:
        """Build the snapshot, sanitize, write to disk, return abs path.

        Returns:
            * absolute path string of the written file on success.
            * ``None`` when the writer is disabled OR when the on-disk
              write failed (failures are logged at WARNING level).

        This method NEVER raises into the caller. Bad input (e.g. missing
        ``request_id``) emits a warning and returns ``None``.
        """
        if not request_id:
            logger.warning(
                "AuditLogger.write skipped: empty request_id (workflowType=%s)",
                workflow_type,
            )
            return None
        if workflow_type not in _VALID_WORKFLOW_TYPES:
            logger.warning(
                "AuditLogger.write skipped: unknown workflowType '%s' for %s",
                workflow_type,
                request_id,
            )
            return None
        if not self._enabled:
            return None

        snapshot: dict[str, Any] = {
            "schemaVersion": self.SCHEMA_VERSION,
            "writtenAt": _now_iso(),
            "requestId": request_id,
            "workflowType": workflow_type,
            "instruction": instruction,
            "eventId": event_id,
            "agentDecisions": dict(agent_decisions or {}),
            "mcpTrace": list(mcp_trace or []),
            "safetyValidation": safety_validation,
            "verification": verification,
            "executionResult": execution_result,
            "finalStatus": str(final_status or "UNKNOWN"),
            "finalAnswer": final_answer,
            "extra": dict(extra or {}),
        }

        # Redact any secret-bearing keys before serializing.
        snapshot = _sanitize(snapshot)

        target = self.file_path(request_id)
        with self._lock:
            try:
                self._directory.mkdir(parents=True, exist_ok=True)
                # ``ensure_ascii=False`` keeps Chinese instructions readable
                # in the saved file; ``default=str`` is a defensive last
                # resort for stray non-JSON-native values (Path, datetime,
                # Enum, set, etc.) that may slip through model dumps.
                with open(target, "w", encoding="utf-8") as f:
                    json.dump(
                        snapshot,
                        f,
                        ensure_ascii=False,
                        indent=2,
                        default=str,
                    )
            except (OSError, TypeError, ValueError) as exc:
                logger.warning(
                    "Failed to write audit file %s: %s", target, exc
                )
                return None
        return str(target)


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_DEFAULT_LOGGER: AuditLogger | None = None
_DEFAULT_LOGGER_LOCK = threading.Lock()


def get_default_audit_logger() -> AuditLogger:
    """Return the lazily-initialized process-wide audit logger.

    Configuration is read from the environment exactly once, on first
    access. Tests should call :func:`reset_default_audit_logger` between
    runs if they mutate ``AUDIT_LOG_DIR`` or ``AUDIT_LOG_DISABLED``.
    """
    global _DEFAULT_LOGGER
    if _DEFAULT_LOGGER is None:
        with _DEFAULT_LOGGER_LOCK:
            if _DEFAULT_LOGGER is None:
                _DEFAULT_LOGGER = AuditLogger()
    return _DEFAULT_LOGGER


def reset_default_audit_logger() -> None:
    """Drop the cached singleton (test hook)."""
    global _DEFAULT_LOGGER
    with _DEFAULT_LOGGER_LOCK:
        _DEFAULT_LOGGER = None


__all__ = [
    "AuditLogger",
    "WORKFLOW_OS_OPS",
    "WORKFLOW_SECURITY_DEFENSE",
    "get_default_audit_logger",
    "reset_default_audit_logger",
    "new_workflow_request_id",
]
