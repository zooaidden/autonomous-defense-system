"""os-mcp-server (FastMCP protocol layer).

This module is intentionally thin: every MCP tool simply forwards to a
function in :mod:`os_service`. All business logic, argument validation and
output shaping live in that module so unit tests can exercise the service
without depending on the ``mcp`` package.

Run modes::

    python server.py        Start the MCP server over stdio.

Tests live in ``test_os_service.py`` and exercise the service module
directly.
"""
from __future__ import annotations

import logging
from typing import Any

import os_service as ops

logger = logging.getLogger("os-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# Soft import of the official MCP SDK.
#
# Allowing this file to load even when the ``mcp`` package is missing keeps
# unit tests and IDE imports lightweight; only ``main()`` actually requires
# the SDK at runtime. The fallback ``_NoOpMCP`` mirrors the one used by
# ``topology-mcp-server`` and ``policy-mcp-server`` so the project's MCP
# servers stay structurally identical.
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("os-mcp-server")
    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # ImportError or any indirect failure

    class _NoOpMCP:
        """Placeholder used when the ``mcp`` package is missing."""

        def tool(self, *_args: Any, **_kwargs: Any):
            def deco(fn):  # type: ignore[no-untyped-def]
                return fn

            return deco

        def resource(self, *_args: Any, **_kwargs: Any):
            def deco(fn):  # type: ignore[no-untyped-def]
                return fn

            return deco

        def run(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(
                "mcp package is not installed; run "
                "`pip install -r requirements.txt` first."
            )

    mcp = _NoOpMCP()  # type: ignore[assignment]
    _MCP_AVAILABLE = False
    _MCP_IMPORT_ERROR = exc


# ---------------------------------------------------------------------------
# MCP tools - thin wrappers around os_service.
#
# Every tool returns the canonical envelope produced by os_service so the
# protocol layer never needs to inspect or rewrap the payload. Forwarding
# is kept to a single line per tool to make the surface area easy to audit.
# ---------------------------------------------------------------------------


@mcp.tool()
def get_process_list(top_n: int = 50) -> dict[str, Any]:
    """List the top ``top_n`` processes by CPU usage (read-only)."""
    return ops.get_process_list(top_n=top_n)


@mcp.tool()
def get_network_sockets(state: str = "all", top_n: int = 500) -> dict[str, Any]:
    """List active network sockets via ``ss`` (falls back to ``netstat``)."""
    return ops.get_network_sockets(state=state, top_n=top_n)


@mcp.tool()
def get_open_files(
    path: str | None = None,
    pid: int | None = None,
    top_n: int = 200,
) -> dict[str, Any]:
    """List open file handles via ``lsof -nP`` (read-only)."""
    return ops.get_open_files(path=path, pid=pid, top_n=top_n)


@mcp.tool()
def get_system_logs(
    unit: str | None = None,
    lines: int = 200,
    since: str | None = None,
) -> dict[str, Any]:
    """Tail recent journal entries via ``journalctl`` (read-only)."""
    return ops.get_system_logs(unit=unit, lines=lines, since=since)


@mcp.tool()
def get_disk_usage() -> dict[str, Any]:
    """Report disk usage for every mounted filesystem via ``df -P -k``."""
    return ops.get_disk_usage()


@mcp.tool()
def get_memory_status() -> dict[str, Any]:
    """Report memory and swap usage via ``/proc/meminfo`` (or ``free`` fallback)."""
    return ops.get_memory_status()


@mcp.tool()
def get_cpu_load() -> dict[str, Any]:
    """Report 1m / 5m / 15m load averages via ``/proc/loadavg``."""
    return ops.get_cpu_load()


@mcp.tool()
def get_uptime() -> dict[str, Any]:
    """Report system uptime, idle time and a pretty summary."""
    return ops.get_uptime()


@mcp.tool()
def get_service_status(service: str) -> dict[str, Any]:
    """Report systemd service status via ``systemctl is-active`` + ``status``."""
    return ops.get_service_status(service=service)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server over stdio (must be invoked by the MCP client)."""
    if not _MCP_AVAILABLE:
        raise RuntimeError(
            "mcp package is not installed; run "
            f"`pip install -r requirements.txt` first. Original error: {_MCP_IMPORT_ERROR!r}"
        )
    logger.info(
        "Starting os-mcp-server with 9 read-only tools (process / sockets / "
        "open files / journal / disk / memory / cpu / uptime / systemd service)"
    )
    mcp.run()


if __name__ == "__main__":
    main()
