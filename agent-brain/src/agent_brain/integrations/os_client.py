"""Client adapter for ``os-mcp-server``.

This module mirrors the structure of
:mod:`agent_brain.integrations.mcp_client` (TopologyMCPClient) and
:mod:`agent_brain.integrations.policy_client` (PolicyMCPClient) but is
deliberately decoupled from them: it neither imports nor mutates either
client, so adding the OS MCP capability to ``agent-brain`` cannot break
the existing ``/workflow/run`` defence-in-depth pipeline.

Two working modes are supported (``disabled`` is reachable only via the
constructor and is not exposed through the env-var contract):

    1. ``local``: load
       ``mcp-servers/os-mcp-server/os_service.py`` directly via
       :mod:`importlib` and call the pure functions in-process. Zero
       deps, zero startup cost; ideal for development and unit tests.

    2. ``real``: spawn ``server.py`` over stdio and talk to it through
       the official MCP Python SDK ``ClientSession``. Requires the
       ``mcp`` package to be installed. Used for staging / production.

Environment variables (constructor arguments override these):

    MCP_OS_MODE              ``local`` or ``real`` (default: ``local``).
    OS_MCP_SERVER_PATH       Absolute / relative path to the
                             ``mcp-servers/os-mcp-server`` *directory*.
                             ``server.py`` is appended internally so the
                             operator never has to point at the script
                             file directly.
    MCP_PYTHON_EXECUTABLE    Interpreter used to spawn ``server.py`` in
                             real mode (default: ``sys.executable``).
                             Shared with topology / policy clients.
    MCP_REQUEST_TIMEOUT_S    Per-call timeout in real mode (default 10s).
                             Shared with topology / policy clients.

Public envelope returned by every tool method::

    {
        "server":  "os-mcp-server",
        "tool":    "<tool_name>",
        "success": true | false,
        "summary": "<human-readable single line>",
        "result":  <tool-specific payload or None>,
        "error":   None | "<machine-readable code>",
    }

The shape is intentionally distinct from PolicyMCPClient /
TopologyMCPClient (which return ``{success, data, message}``) because
the OS server itself returns ``{success, tool, data, summary, error}``
and the calling code (future ``OpsOrchestrator``, dashboard ``/ops``
page) wants to display a uniform record per call without an extra join.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from types import ModuleType
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# __file__ -> .../agent-brain/src/agent_brain/integrations/os_client.py
# parents[4] -> autonomous-defense-system/
_AGENT_BRAIN_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_SERVER_PATH = _AGENT_BRAIN_ROOT / "mcp-servers" / "os-mcp-server"

# Stable identifier emitted in every envelope so consumers can render the
# originating server alongside the tool name without an extra lookup.
_SERVER_NAME = "os-mcp-server"

# Mode constants. ``disabled`` is reachable only by passing
# ``OsMCPClient(enabled=False)``; the public env-var contract exposes
# ``local`` / ``real`` only.
MODE_DISABLED = "disabled"
MODE_LOCAL = "local"
MODE_REAL = "real"

# Method-name to MCP tool-name map. Today they happen to match 1:1, but
# keeping a registry decouples wire names from Python identifiers and
# makes the public surface obvious at a glance.
_TOOL_NAMES = {
    "get_process_list": "get_process_list",
    "get_network_sockets": "get_network_sockets",
    "get_open_files": "get_open_files",
    "get_system_logs": "get_system_logs",
    "get_disk_usage": "get_disk_usage",
    "get_memory_status": "get_memory_status",
    "get_cpu_load": "get_cpu_load",
    "get_uptime": "get_uptime",
    "get_service_status": "get_service_status",
}


# ---------------------------------------------------------------------------
# Soft import of the official MCP SDK. Local / disabled modes must keep
# working even if the package is missing - this matches the pattern used
# by the other two MCP clients in this package.
# ---------------------------------------------------------------------------

try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore

    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # ImportError or anything else means unavailable
    _MCP_AVAILABLE = False
    _MCP_IMPORT_ERROR = _exc
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


def is_mcp_sdk_installed() -> bool:
    """Public probe used by ``/health`` to report MCP SDK availability."""
    return _MCP_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean env var: accepts 1 / true / yes / on (case-insensitive)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _build_envelope(tool: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Project an underlying os_service envelope into the Client envelope.

    The os_service envelope is ``{success, tool, data, summary, error}``;
    we rename ``data`` to ``result``, prepend ``server``, and tolerate
    missing keys so callers always see the full schema.
    """
    return {
        "server": _SERVER_NAME,
        "tool": tool,
        "success": bool(raw.get("success")),
        "summary": str(raw.get("summary") or ""),
        "result": raw.get("data"),
        "error": raw.get("error"),
    }


def _client_error_envelope(
    tool: str,
    summary: str,
    error: str,
) -> dict[str, Any]:
    """Build a Client-originated failure envelope.

    Used when the failure happens *before* the underlying tool ever runs:
    MCP disabled, mcp package missing in real mode, server.py missing,
    timeout in real mode, etc. The shape stays identical to the success
    envelope so consumers do not need to branch.
    """
    return {
        "server": _SERVER_NAME,
        "tool": tool,
        "success": False,
        "summary": summary,
        "result": None,
        "error": error,
    }


def _resolve_mode(enabled: bool, mode_hint: str | None) -> str:
    """Collapse ``(enabled, mode_hint)`` into a single mode constant."""
    if not enabled:
        return MODE_DISABLED
    chosen = (mode_hint or MODE_LOCAL).strip().lower()
    if chosen not in (MODE_LOCAL, MODE_REAL):
        # Unknown values fall back to ``local`` so callers still get a
        # functional client instead of a hard error.
        logger.warning("unknown MCP_OS_MODE=%r, falling back to 'local'", chosen)
        return MODE_LOCAL
    return chosen


# ---------------------------------------------------------------------------
# OsMCPClient
# ---------------------------------------------------------------------------


class OsMCPClient:
    """Unified client for ``os-mcp-server``.

    Usage::

        # 1) Ad-hoc one-shot call (unit tests, scripts)
        async def demo():
            client = OsMCPClient()  # reads env vars
            try:
                env = await client.get_disk_usage()
            finally:
                await client.aclose()

        # 2) Recommended: lifecycle managed by ``async with``
        async with OsMCPClient() as client:
            env = await client.get_service_status("sshd")

    All constructor arguments are optional; missing values are pulled
    from environment variables, then from safe built-in defaults. The
    client never imports ``TopologyMCPClient`` / ``PolicyMCPClient`` so
    enabling OS MCP cannot affect the existing ``/workflow/run`` flow.
    """

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        mode: str | None = None,
        server_path: str | os.PathLike[str] | None = None,
        python_executable: str | None = None,
        request_timeout: float | None = None,
    ) -> None:
        # 1) Enable flag.
        #
        # Unlike PolicyMCPClient (which honours the global ``ENABLE_MCP``
        # gate), the OS client defaults to enabled=True because the OS
        # perception capability is opt-in per request from the operator
        # rather than an integral part of /workflow/run.
        self._enabled = True if enabled is None else bool(enabled)

        # 2) Concrete mode (disabled / local / real).
        self._mode = _resolve_mode(
            self._enabled,
            mode if mode is not None else os.environ.get("MCP_OS_MODE"),
        )

        # 3) os-mcp-server *directory* (server.py is joined internally).
        path_str = (
            str(server_path)
            if server_path is not None
            else os.environ.get("OS_MCP_SERVER_PATH")
        )
        self._server_path: Path = (
            Path(path_str).expanduser().resolve()
            if path_str
            else _DEFAULT_SERVER_PATH
        )

        # 4) Python interpreter used to spawn server.py in real mode.
        #    Reuses the same env var as the other MCP clients on purpose.
        self._python_executable = (
            python_executable
            or os.environ.get("MCP_PYTHON_EXECUTABLE")
            or sys.executable
        )

        # 5) Per-call timeout in real mode. Same env var as siblings.
        if request_timeout is not None:
            self._timeout = float(request_timeout)
        else:
            try:
                self._timeout = float(os.environ.get("MCP_REQUEST_TIMEOUT_S", "10"))
            except ValueError:
                self._timeout = 10.0

        # Lazily-loaded local module cache.
        self._os_service: ModuleType | None = None
        # Real-mode async lifecycle handles.
        self._exit_stack: AsyncExitStack | None = None
        self._session: Any = None

        logger.info(
            "OsMCPClient initialized: enabled=%s mode=%s server_path=%s",
            self._enabled,
            self._mode,
            self._server_path,
        )

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether the client is operational (False -> disabled mode)."""
        return self._enabled

    @property
    def mode(self) -> str:
        """Effective mode: ``disabled`` / ``local`` / ``real``."""
        return self._mode

    @property
    def server_path(self) -> Path:
        """Path to the os-mcp-server directory (server.py joined internally)."""
        return self._server_path

    # ------------------------------------------------------------------
    # Async lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "OsMCPClient":
        # Eagerly establish the stdio session in real mode; no-op otherwise.
        if self._mode == MODE_REAL:
            await self._ensure_real_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Tear down the stdio subprocess and session. Idempotent."""
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception as exc:  # closing must never propagate to callers
                logger.warning("error closing OS MCP session: %s", exc)
            finally:
                self._exit_stack = None
                self._session = None

    # ------------------------------------------------------------------
    # Public tool methods (1-to-1 with os-mcp-server tools)
    # ------------------------------------------------------------------

    async def get_process_list(self, top_n: int = 50) -> dict[str, Any]:
        """List the top ``top_n`` processes by CPU usage."""
        return await self._dispatch("get_process_list", {"top_n": int(top_n)})

    async def get_network_sockets(
        self,
        state: str = "all",
        top_n: int = 500,
    ) -> dict[str, Any]:
        """List active network sockets via ``ss`` (falls back to ``netstat``)."""
        return await self._dispatch(
            "get_network_sockets",
            {"state": str(state), "top_n": int(top_n)},
        )

    async def get_open_files(
        self,
        path: str | None = None,
        pid: int | None = None,
        top_n: int = 200,
    ) -> dict[str, Any]:
        """List open file handles via ``lsof -nP``."""
        return await self._dispatch(
            "get_open_files",
            {"path": path, "pid": pid, "top_n": int(top_n)},
        )

    async def get_system_logs(
        self,
        unit: str | None = None,
        lines: int = 200,
        since: str | None = None,
    ) -> dict[str, Any]:
        """Tail recent journal entries via ``journalctl``."""
        return await self._dispatch(
            "get_system_logs",
            {"unit": unit, "lines": int(lines), "since": since},
        )

    async def get_disk_usage(self) -> dict[str, Any]:
        """Report disk usage for every mounted filesystem via ``df -P -k``."""
        return await self._dispatch("get_disk_usage", {})

    async def get_memory_status(self) -> dict[str, Any]:
        """Report memory and swap usage via ``/proc/meminfo``."""
        return await self._dispatch("get_memory_status", {})

    async def get_cpu_load(self) -> dict[str, Any]:
        """Report 1m / 5m / 15m load averages via ``/proc/loadavg``."""
        return await self._dispatch("get_cpu_load", {})

    async def get_uptime(self) -> dict[str, Any]:
        """Report system uptime, idle time and a pretty summary."""
        return await self._dispatch("get_uptime", {})

    async def get_service_status(self, service_name: str) -> dict[str, Any]:
        """Report systemd service status via ``systemctl``.

        ``service_name`` is forwarded as-is; ``os_service`` performs
        regex-based whitelist validation and rejects shell metacharacters
        before any subprocess invocation.
        """
        return await self._dispatch(
            "get_service_status",
            {"service": str(service_name)},
        )

    # ------------------------------------------------------------------
    # Dispatcher: unified disabled / local / real handling
    # ------------------------------------------------------------------

    async def _dispatch(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call to the active mode and never raise to callers."""
        if self._mode == MODE_DISABLED:
            return _client_error_envelope(
                tool,
                "OS MCP integration is disabled (set MCP_OS_MODE=local or real to enable)",
                "client_disabled",
            )

        try:
            if self._mode == MODE_LOCAL:
                return await self._call_local(tool, arguments)
            if self._mode == MODE_REAL:
                return await self._call_real(tool, arguments)
            # Unreachable in practice: ``_resolve_mode`` already collapses values.
            return _client_error_envelope(
                tool,
                f"unsupported MCP mode: {self._mode}",
                "client_error",
            )
        except Exception as exc:  # last-resort guard: wrap into failure envelope
            logger.exception("OS MCP tool '%s' failed", tool)
            return _client_error_envelope(
                tool,
                f"{tool} failed: {exc.__class__.__name__}: {exc}",
                "client_error",
            )

    # ------------------------------------------------------------------
    # Local mode: in-process call into os_service.py
    # ------------------------------------------------------------------

    async def _call_local(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call ``os_service.<tool>`` directly. CPU-bound and fast.

        os_service tools are guaranteed to never raise (they catch
        FileNotFoundError / TimeoutExpired / OSError internally and
        return a structured envelope), so we simply forward the
        keyword arguments and project the response.
        """
        ops = self._load_os_service()

        if tool == "get_process_list":
            raw = ops.get_process_list(top_n=arguments.get("top_n", 50))
        elif tool == "get_network_sockets":
            raw = ops.get_network_sockets(
                state=arguments.get("state", "all"),
                top_n=arguments.get("top_n", 500),
            )
        elif tool == "get_open_files":
            raw = ops.get_open_files(
                path=arguments.get("path"),
                pid=arguments.get("pid"),
                top_n=arguments.get("top_n", 200),
            )
        elif tool == "get_system_logs":
            raw = ops.get_system_logs(
                unit=arguments.get("unit"),
                lines=arguments.get("lines", 200),
                since=arguments.get("since"),
            )
        elif tool == "get_disk_usage":
            raw = ops.get_disk_usage()
        elif tool == "get_memory_status":
            raw = ops.get_memory_status()
        elif tool == "get_cpu_load":
            raw = ops.get_cpu_load()
        elif tool == "get_uptime":
            raw = ops.get_uptime()
        elif tool == "get_service_status":
            raw = ops.get_service_status(service=arguments.get("service", ""))
        else:
            return _client_error_envelope(
                tool,
                f"unknown local tool: {tool}",
                "client_error",
            )

        if not isinstance(raw, dict):
            return _client_error_envelope(
                tool,
                f"os_service.{tool} returned non-dict response",
                "client_error",
            )
        return _build_envelope(tool, raw)

    def _load_os_service(self) -> ModuleType:
        """Load os_service.py via importlib without polluting sys.path.

        The module is cached per-instance so subsequent local calls are
        plain function invocations. The path validation here is what
        prevents an obviously-misconfigured ``OS_MCP_SERVER_PATH`` from
        manifesting as an opaque ``ImportError`` deep in importlib.
        """
        if self._os_service is not None:
            return self._os_service
        if not self._server_path.exists():
            raise FileNotFoundError(
                f"os mcp server path does not exist: {self._server_path}"
            )
        module_path = self._server_path / "os_service.py"
        if not module_path.exists():
            raise FileNotFoundError(
                f"os_service.py not found at: {module_path}"
            )
        spec = importlib.util.spec_from_file_location(
            "agent_brain_os_service_local", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build module spec for: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._os_service = module
        return module

    # ------------------------------------------------------------------
    # Real mode: stdio subprocess + MCP ClientSession
    # ------------------------------------------------------------------

    async def _call_real(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Forward the call through MCP ``ClientSession.call_tool``.

        The check for ``_MCP_AVAILABLE`` is intentionally done inside
        ``_ensure_real_session`` so that tests can inject a fake session
        without installing the ``mcp`` package.
        """
        try:
            session = await self._ensure_real_session()
        except FileNotFoundError as exc:
            return _client_error_envelope(tool, str(exc), "tool_unavailable")
        except RuntimeError as exc:
            # mcp package missing -> client_error so callers can branch.
            return _client_error_envelope(tool, str(exc), "client_error")

        tool_name = _TOOL_NAMES.get(tool, tool)
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool_name, arguments),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return _client_error_envelope(
                tool,
                f"MCP tool '{tool_name}' timed out after {self._timeout}s",
                "timeout",
            )
        return self._parse_tool_result(tool, result)

    async def _ensure_real_session(self) -> Any:
        """Lazily build the stdio session bound to ``self._exit_stack``.

        Tests may pre-inject ``self._session`` to bypass the subprocess.
        ``server.py`` is appended to ``self._server_path`` here so the
        operator only ever has to point at the directory.
        """
        if self._session is not None:
            return self._session
        if not _MCP_AVAILABLE:
            raise RuntimeError(
                "mcp package not installed; install via "
                f"`pip install -e .[mcp]` or set MCP_OS_MODE=local. "
                f"Original error: {_MCP_IMPORT_ERROR!r}"
            )
        if not self._server_path.exists():
            raise FileNotFoundError(
                f"os mcp server directory does not exist: {self._server_path}"
            )
        server_script = self._server_path / "server.py"
        if not server_script.exists():
            raise FileNotFoundError(
                f"server.py not found at: {server_script}"
            )

        stack = AsyncExitStack()
        await stack.__aenter__()
        try:
            params = StdioServerParameters(
                command=self._python_executable,
                args=[str(server_script)],
                # Inherit PATH/PYTHONPATH from the parent; do not override.
                env=None,
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception:
            # Roll back any contexts we already entered.
            await stack.aclose()
            raise

        self._exit_stack = stack
        self._session = session
        return session

    @staticmethod
    def _parse_tool_result(tool: str, result: Any) -> dict[str, Any]:
        """Decode an MCP ``CallToolResult`` into the OsMCPClient envelope.

        os-mcp-server emits the canonical
        ``{success, tool, data, summary, error}`` shape via
        ``structuredContent`` (MCP >=1.2) and also as JSON text in
        ``content[0]``. Both are handled; anything else collapses into a
        Client-side ``command_failed`` envelope so the FE never has to
        defend against partially-populated rows.
        """
        # 1) Error result: extract any embedded text content.
        if getattr(result, "isError", False):
            msgs: list[str] = []
            for item in getattr(result, "content", []) or []:
                text = getattr(item, "text", None)
                if text:
                    msgs.append(str(text))
            return _client_error_envelope(
                tool,
                "; ".join(msgs) or "tool returned error",
                "command_failed",
            )

        # 2) Prefer MCP >=1.2 structured output if present.
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            return _build_envelope(tool, structured)

        # 3) Fall back to ``content[0].text``.
        content = getattr(result, "content", []) or []
        if not content:
            return _client_error_envelope(
                tool,
                "empty MCP response",
                "command_failed",
            )
        first = content[0]
        text = getattr(first, "text", None)
        if not text:
            return _client_error_envelope(
                tool,
                f"unsupported MCP content type: {type(first).__name__}",
                "command_failed",
            )
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return _client_error_envelope(
                tool,
                f"non-json MCP response: {text[:200]}",
                "command_failed",
            )
        if isinstance(parsed, dict):
            return _build_envelope(tool, parsed)
        return _client_error_envelope(
            tool,
            "MCP response is not an object",
            "command_failed",
        )


__all__ = [
    "MODE_DISABLED",
    "MODE_LOCAL",
    "MODE_REAL",
    "OsMCPClient",
    "is_mcp_sdk_installed",
]
