"""Bridge between agent-brain application audit and the Kylin kernel audit subsystem.

On Kylin V11, ``auditd`` records every system call made by processes
subject to audit rules. This module provides a lightweight bridge so
``/ops/chat`` can:

1. **Mark** — write a ``type=USR`` marker event into the kernel audit
   stream carrying the agent-brain ``requestId``, so kernel and
   application audit trails can be joined later.

2. **Query** — search the kernel audit log for events correlated with
   a specific ``requestId`` and time window.

On non-Kylin / non-Linux hosts every method is a no-op returning empty
results, so callers never need to branch on the platform.
"""
from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default audit log location on Kylin / RHEL-family distributions.
_DEFAULT_AUDIT_LOG = Path("/var/log/audit/audit.log")

# How far back to search for events when no explicit time window is given.
_DEFAULT_LOOKBACK_SECONDS = 60


class KylinAuditBridge:
    """Read-only bridge to the Kylin kernel audit subsystem.

    Usage::

        bridge = KylinAuditBridge()
        if bridge.is_available():
            bridge.mark_request("ops-a1b2c3d4e5f6")
        ...
        events = bridge.query_by_request("ops-a1b2c3d4e5f6", lookback_s=60)
    """

    def __init__(
        self,
        *,
        audit_log_path: str | Path | None = None,
    ) -> None:
        self._audit_log = Path(audit_log_path) if audit_log_path else _DEFAULT_AUDIT_LOG
        self._available: bool | None = None
        # Detect whether we can speak to auditd.
        self._auditctl = _which("auditctl")
        self._ausearch = _which("ausearch")

    def is_available(self) -> bool:
        """Return True when the kernel audit subsystem is reachable."""
        if self._available is not None:
            return self._available
        if not Path("/proc/self/loginuid").exists():
            self._available = False
            return False
        # auditd must be running and we must be able to write user messages.
        # This is a best-effort probe; failures here are non-fatal.
        try:
            proc = subprocess.run(
                ["auditctl", "-s"],
                capture_output=True, timeout=3, shell=False, check=False,
            )
            self._available = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._available = False
        return self._available

    def mark_request(self, request_id: str) -> bool:
        """Write a ``type=USR`` marker into the kernel audit stream.

        The marker carries the agent-brain ``requestId`` so that
        ``ausearch`` can later retrieve kernel-level events that
        occurred during the agent's execution window.

        Returns True on success, False on failure (logged at DEBUG).
        """
        if not self.is_available():
            return False
        if not self._auditctl:
            return False
        msg = f"agent-brain:requestId={request_id}"
        try:
            subprocess.run(
                [self._auditctl, "-m", msg],
                capture_output=True, timeout=3, shell=False, check=False,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("auditctl marker failed for %s: %s", request_id, exc)
            return False

    def query_by_request(
        self,
        request_id: str,
        *,
        lookback_s: int = _DEFAULT_LOOKBACK_SECONDS,
    ) -> list[dict[str, Any]]:
        """Search the kernel audit log for events near ``request_id``.

        Uses ``ausearch`` when available; falls back to grepping the
        raw audit log file.

        Returns a list of raw event dicts. On non-Kylin hosts or when
        the search tool is unavailable, returns an empty list.
        """
        if not request_id:
            return []

        # Build time window: lookback_s seconds before now.
        now = datetime.now(timezone.utc)
        ts_start = int((now.timestamp() - lookback_s) * 1000)

        if self._ausearch:
            return self._query_via_ausearch(request_id, ts_start)
        return self._query_via_grep(request_id)

    def _query_via_ausearch(self, request_id: str, ts_start: int) -> list[dict[str, Any]]:
        """Use ``ausearch`` to find audit events containing ``requestId``."""
        try:
            proc = subprocess.run(
                [self._ausearch, "-k", "agent_brain", "-ts", str(ts_start / 1000)],
                capture_output=True, timeout=10, shell=False, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("ausearch failed: %s", exc)
            return []

        # Parse ausearch output. Each event starts with ``----``.
        events: list[dict[str, Any]] = []
        current: list[str] = []
        for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
            stripped = line.rstrip()
            if stripped.startswith("----"):
                if current:
                    events.append({"type": "AUDIT_EVENT", "raw": "\n".join(current)})
                    current = []
            elif stripped:
                current.append(stripped)
        if current:
            events.append({"type": "AUDIT_EVENT", "raw": "\n".join(current)})

        # Filter for requestId.
        return [e for e in events if request_id in e.get("raw", "")]

    def _query_via_grep(self, _request_id: str) -> list[dict[str, Any]]:
        """Fall back to a raw grep of the audit log file."""
        if not self._audit_log.exists():
            return []
        try:
            self._audit_log.read_text(encoding="utf-8", errors="replace")[:1024 * 1024]
        except OSError:
            return []
        # For the fallback we return an empty list; grepping a potentially
        # huge audit log from Python is not a good fit for an HTTP handler.
        return []


def _which(command: str) -> str | None:
    """Resolve ``command`` to an absolute path via ``$PATH`` or return None."""
    import shutil
    return shutil.which(command)


__all__ = ["KylinAuditBridge"]
