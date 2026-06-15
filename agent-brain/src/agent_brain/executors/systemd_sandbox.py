"""Wrap subprocess commands with ``systemd-run --user --scope`` sandboxing.

On systemd-based Linux hosts (Kylin V11, Ubuntu, etc.), ``systemd-run``
provides kernel-level resource isolation via cgroups v2 **without**
requiring root privileges (``--user`` mode). This module acts as a
transparent wrapper: when systemd is available the command gets cgroup
containment; when it isn't (Windows, macOS, containers without systemd)
the command runs via plain ``subprocess.run`` unmodified.

Isolation provided (when systemd is available):

    * MemoryMax     — OOM-killer trigger for the transient scope
    * CPUQuota      — percentage cap on CPU time
    * TasksMax      — process-count limit (fork-bomb protection)
    * PrivateTmp    — per-command private /tmp
    * NoNewPrivileges — kernel-level privilege-escalation block
    * ProtectSystem=strict — read-only /usr, /etc, /boot (writable only
      in paths explicitly listed in ReadWritePaths)

The class is intentionally decoupled from ``LeastPrivilegeExecutor`` so
unit tests can inject ``use_sandbox=False`` and the sandbox itself can
be tested independently.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default resource limits. Conservative: suitable for ``ps``, ``ss``,
# ``journalctl -n 200`` on a typical Kylin host.
DEFAULT_MEMORY_MAX = "256M"
DEFAULT_CPU_QUOTA = "50%"  # percent of one core
DEFAULT_TASKS_MAX = 50
DEFAULT_TIMEOUT_SECONDS = 30  # systemd-run may add overhead on cold start


@dataclass(frozen=True)
class SandboxLimits:
    """Resource limits applied to a sandboxed command."""
    memory_max: str = DEFAULT_MEMORY_MAX
    cpu_quota: str = DEFAULT_CPU_QUOTA
    tasks_max: int = DEFAULT_TASKS_MAX
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    read_write_paths: list[str] | None = None  # paths to keep writable


class SystemdSandbox:
    """Wrap a command with ``systemd-run --user --scope`` sandboxing.

    Usage::

        sandbox = SystemdSandbox()
        if sandbox.is_available():
            wrapped_argv = sandbox.wrap_command(["ps", "-ef"])
            # -> ["systemd-run", "--user", "--scope", "-p", "MemoryMax=256M", ...,
            #      "--", "ps", "-ef"]
        else:
            wrapped_argv = ["ps", "-ef"]  # run bare

    ``is_available()`` caches its result; call ``reset()`` between
    tests that mutate the environment.
    """

    def __init__(self, *, limits: SandboxLimits | None = None) -> None:
        self._limits = limits or SandboxLimits()
        self._available: bool | None = None

    def is_available(self) -> bool:
        """Return True when systemd-run (user scope) is usable on this host.

        On Kylin V11 (systemd >= 249) this returns True for non-root
        users. On Windows, macOS, and containers without systemd this
        returns False.
        """
        if self._available is not None:
            return self._available

        # systemd-run must exist on PATH.
        if shutil.which("systemd-run") is None:
            logger.debug("systemd_sandbox: systemd-run not found on PATH")
            self._available = False
            return False

        # Must be able to talk to the user manager (systemd --user).
        try:
            proc = subprocess.run(
                ["systemctl", "--user", "is-system-running"],
                capture_output=True,
                timeout=5,
                shell=False,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._available = False
            return False

        # ``is-system-running`` exits 0 for "running" / "degraded" but
        # non-zero when the user manager is not reachable (e.g. inside a
        # Docker container that only has PID 1 systemd but no user bus).
        if proc.returncode != 0:
            logger.debug(
                "systemd_sandbox: systemd user manager not reachable (exit=%s)",
                proc.returncode,
            )
            self._available = False
            return False

        self._available = True
        return True

    def reset(self) -> None:
        """Clear the cached availability check (test hook)."""
        self._available = None

    def wrap_command(self, argv: list[str]) -> list[str]:
        """Return ``systemd-run ... -- <argv>`` or bare ``argv``.

        When the sandbox is unavailable the original argv is returned
        unchanged so callers can use this unconditionally.

        The ``--`` separator ensures argv elements are never parsed as
        systemd-run options even if they start with ``-``.
        """
        if not self.is_available():
            return list(argv)

        limits = self._limits
        prefix = [
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "-p", f"MemoryMax={limits.memory_max}",
            "-p", f"CPUQuota={limits.cpu_quota}",
            "-p", f"TasksMax={limits.tasks_max}",
            "-p", "PrivateTmp=yes",
            "-p", "NoNewPrivileges=yes",
            "-p", "ProtectSystem=strict",
            "-p", "ProtectHome=read-only",
            "-p", "ProtectClock=yes",
            "-p", "RestrictSUIDSGID=yes",
            "-p", "MemoryDenyWriteExecute=yes",
        ]

        # Allow writes to /tmp so commands can create temp files.
        rw_paths = list(limits.read_write_paths or [])
        if "/tmp" not in rw_paths:
            rw_paths.append("/tmp")
        for p in rw_paths:
            prefix.extend(["-p", f"ReadWritePaths={p}"])

        prefix.append("--")
        return prefix + list(argv)

    def build_envelope(self, was_sandboxed: bool) -> dict[str, Any]:
        """Return the ``sandbox`` field for executor audit envelopes."""
        return {
            "type": "systemd-run" if was_sandboxed else "none",
            "available": self.is_available(),
            "limits": {
                "memoryMax": self._limits.memory_max,
                "cpuQuota": self._limits.cpu_quota,
                "tasksMax": self._limits.tasks_max,
            } if was_sandboxed else None,
        }


# Convenience function for one-shot use.
def wrap_if_available(argv: list[str], *, limits: SandboxLimits | None = None) -> list[str]:
    """Shortcut: wrap ``argv`` with systemd-run when available, else return as-is."""
    return SystemdSandbox(limits=limits).wrap_command(argv)


__all__ = [
    "DEFAULT_MEMORY_MAX",
    "DEFAULT_CPU_QUOTA",
    "DEFAULT_TASKS_MAX",
    "DEFAULT_TIMEOUT_SECONDS",
    "SandboxLimits",
    "SystemdSandbox",
    "wrap_if_available",
]
