"""Client adapter for ``kylinsec-mcp-server``.

Mirrors the structure of :class:`OsMCPClient` but is deliberately
decoupled — it neither imports nor mutates the OS / topology / policy
clients, so adding KylinSec MCP cannot break the existing
``/workflow/run`` pipeline.

Two working modes:

    1. ``local`` — import ``kylinsec_service.py`` via :mod:`importlib`
       and call the pure functions in-process. Recommended for Kylin V11
       where the server is co-located.

    2. ``real`` — spawn ``server.py`` over stdio via the MCP Python SDK.

Environment variables (constructor arguments override):

    MCP_KYLINSEC_MODE        ``local`` or ``real`` (default: ``local``).
    KYLINSEC_MCP_SERVER_PATH Path to the ``kylinsec-mcp-server`` *directory*.
    MCP_PYTHON_EXECUTABLE    Interpreter for real-mode child process.
    MCP_REQUEST_TIMEOUT_S    Per-call timeout (default 10s).

Public envelope::

    {
        "server":  "kylinsec-mcp-server",
        "tool":    "<tool_name>",
        "success": true | false,
        "summary": "<human-readable single line>",
        "result":  <tool-specific payload or None>,
        "error":   None | "<machine-readable code>",
    }
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
# Path resolution
# ---------------------------------------------------------------------------

_AGENT_BRAIN_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_SERVER_PATH = _AGENT_BRAIN_ROOT / "mcp-servers" / "kylinsec-mcp-server"

_SERVER_NAME = "kylinsec-mcp-server"

MODE_DISABLED = "disabled"
MODE_LOCAL = "local"
MODE_REAL = "real"

_TOOL_NAMES = {
    "get_kylinsec_status": "get_kylinsec_status",
    "get_tcm_pcrs": "get_tcm_pcrs",
    "verify_binary_ima": "verify_binary_ima",
    "get_kernel_module_signatures": "get_kernel_module_signatures",
    "get_kylin_patch_level": "get_kylin_patch_level",
    "check_seccomp_arch": "check_seccomp_arch",
    "get_kylin_audit_policy": "get_kylin_audit_policy",
}

# ---------------------------------------------------------------------------
# Soft import of the official MCP SDK.
# ---------------------------------------------------------------------------

try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore

    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as _exc:
    _MCP_AVAILABLE = False
    _MCP_IMPORT_ERROR = _exc
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


def is_mcp_sdk_installed() -> bool:
    return _MCP_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _build_envelope(tool: str, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "server": _SERVER_NAME,
        "tool": tool,
        "success": bool(raw.get("success")),
        "summary": str(raw.get("summary") or ""),
        "result": raw.get("data"),
        "error": raw.get("error"),
    }


def _client_error_envelope(tool: str, summary: str, error: str) -> dict[str, Any]:
    return {
        "server": _SERVER_NAME,
        "tool": tool,
        "success": False,
        "summary": summary,
        "result": None,
        "error": error,
    }


def _resolve_mode(enabled: bool, mode_hint: str | None) -> str:
    if not enabled:
        return MODE_DISABLED
    chosen = (mode_hint or MODE_LOCAL).strip().lower()
    if chosen not in (MODE_LOCAL, MODE_REAL):
        logger.warning("unknown MCP_KYLINSEC_MODE=%r, falling back to 'local'", chosen)
        return MODE_LOCAL
    return chosen


# ---------------------------------------------------------------------------
# KylinsecMCPClient
# ---------------------------------------------------------------------------


class KylinsecMCPClient:
    """Unified client for ``kylinsec-mcp-server``.

    Auto-detects non-Kylin hosts and disables itself gracefully.
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
        # Auto-detect Kylin platform; disable on non-Linux / non-Kylin.
        self._platform_kylin = Path("/etc/kylin-release").exists() or os.name != "posix"
        if enabled is None:
            self._enabled = self._platform_kylin
        else:
            self._enabled = bool(enabled)

        self._mode = _resolve_mode(
            self._enabled,
            mode if mode is not None else os.environ.get("MCP_KYLINSEC_MODE"),
        )

        path_str = (
            str(server_path)
            if server_path is not None
            else os.environ.get("KYLINSEC_MCP_SERVER_PATH")
        )
        self._server_path: Path = (
            Path(path_str).expanduser().resolve() if path_str else _DEFAULT_SERVER_PATH
        )

        self._python_executable = (
            python_executable
            or os.environ.get("MCP_PYTHON_EXECUTABLE")
            or sys.executable
        )

        if request_timeout is not None:
            self._timeout = float(request_timeout)
        else:
            try:
                self._timeout = float(os.environ.get("MCP_REQUEST_TIMEOUT_S", "10"))
            except ValueError:
                self._timeout = 10.0

        self._service: ModuleType | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._session: Any = None

        logger.info(
            "KylinsecMCPClient initialized: enabled=%s mode=%s server_path=%s platform_kylin=%s",
            self._enabled,
            self._mode,
            self._server_path,
            self._platform_kylin,
        )

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def server_path(self) -> Path:
        return self._server_path

    # ------------------------------------------------------------------
    # Async lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "KylinsecMCPClient":
        if self._mode == MODE_REAL:
            await self._ensure_real_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception as exc:
                logger.warning("error closing KylinSec MCP session: %s", exc)
            finally:
                self._exit_stack = None
                self._session = None

    # ------------------------------------------------------------------
    # Public tool methods
    # ------------------------------------------------------------------

    async def get_kylinsec_status(self) -> dict[str, Any]:
        return await self._dispatch("get_kylinsec_status", {})

    async def get_tcm_pcrs(self) -> dict[str, Any]:
        return await self._dispatch("get_tcm_pcrs", {})

    async def verify_binary_ima(self, path: str = "") -> dict[str, Any]:
        return await self._dispatch("verify_binary_ima", {"path": str(path)})

    async def get_kernel_module_signatures(self) -> dict[str, Any]:
        return await self._dispatch("get_kernel_module_signatures", {})

    async def get_kylin_patch_level(self) -> dict[str, Any]:
        return await self._dispatch("get_kylin_patch_level", {})

    async def check_seccomp_arch(self) -> dict[str, Any]:
        return await self._dispatch("check_seccomp_arch", {})

    async def get_kylin_audit_policy(self) -> dict[str, Any]:
        return await self._dispatch("get_kylin_audit_policy", {})

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    async def _dispatch(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._mode == MODE_DISABLED:
            return _client_error_envelope(
                tool,
                "KylinSec MCP integration is disabled (set MCP_KYLINSEC_MODE=local or real)",
                "client_disabled",
            )
        try:
            if self._mode == MODE_LOCAL:
                return await self._call_local(tool, arguments)
            if self._mode == MODE_REAL:
                return await self._call_real(tool, arguments)
            return _client_error_envelope(tool, f"unsupported mode: {self._mode}", "client_error")
        except Exception as exc:
            logger.exception("KylinSec MCP tool '%s' failed", tool)
            return _client_error_envelope(
                tool, f"{tool} failed: {exc.__class__.__name__}: {exc}", "client_error"
            )

    # ------------------------------------------------------------------
    # Local mode
    # ------------------------------------------------------------------

    async def _call_local(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        svc = self._load_service()
        method = getattr(svc, tool, None)
        if method is None or not callable(method):
            return _client_error_envelope(tool, f"unknown local tool: {tool}", "client_error")

        if tool == "verify_binary_ima":
            raw = method(path=arguments.get("path", ""))
        else:
            raw = method()

        if not isinstance(raw, dict):
            return _client_error_envelope(tool, f"{tool} returned non-dict", "client_error")
        return _build_envelope(tool, raw)

    def _load_service(self) -> ModuleType:
        if self._service is not None:
            return self._service
        if not self._server_path.exists():
            raise FileNotFoundError(f"kylinsec mcp server path does not exist: {self._server_path}")
        module_path = self._server_path / "kylinsec_service.py"
        if not module_path.exists():
            raise FileNotFoundError(f"kylinsec_service.py not found at: {module_path}")
        spec = importlib.util.spec_from_file_location("agent_brain_kylinsec_service_local", module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build module spec for: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._service = module
        return module

    # ------------------------------------------------------------------
    # Real mode
    # ------------------------------------------------------------------

    async def _call_real(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            session = await self._ensure_real_session()
        except FileNotFoundError as exc:
            return _client_error_envelope(tool, str(exc), "tool_unavailable")
        except RuntimeError as exc:
            return _client_error_envelope(tool, str(exc), "client_error")

        tool_name = _TOOL_NAMES.get(tool, tool)
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool_name, arguments),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return _client_error_envelope(
                tool, f"MCP tool '{tool_name}' timed out after {self._timeout}s", "timeout"
            )
        return self._parse_tool_result(tool, result)

    async def _ensure_real_session(self) -> Any:
        if self._session is not None:
            return self._session
        if not _MCP_AVAILABLE:
            raise RuntimeError(
                f"mcp package not installed; install via `pip install -e .[mcp]` "
                f"or set MCP_KYLINSEC_MODE=local. Original error: {_MCP_IMPORT_ERROR!r}"
            )
        if not self._server_path.exists():
            raise FileNotFoundError(f"kylinsec mcp server directory does not exist: {self._server_path}")
        server_script = self._server_path / "server.py"
        if not server_script.exists():
            raise FileNotFoundError(f"server.py not found at: {server_script}")

        stack = AsyncExitStack()
        await stack.__aenter__()
        try:
            params = StdioServerParameters(
                command=self._python_executable,
                args=[str(server_script)],
                env=None,
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception:
            await stack.aclose()
            raise

        self._exit_stack = stack
        self._session = session
        return session

    @staticmethod
    def _parse_tool_result(tool: str, result: Any) -> dict[str, Any]:
        if getattr(result, "isError", False):
            msgs = [str(getattr(i, "text", "")) for i in (getattr(result, "content", []) or []) if getattr(i, "text", None)]
            return _client_error_envelope(tool, "; ".join(msgs) or "tool returned error", "command_failed")

        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            return _build_envelope(tool, structured)

        content = getattr(result, "content", []) or []
        if not content:
            return _client_error_envelope(tool, "empty MCP response", "command_failed")
        first = content[0]
        text = getattr(first, "text", None)
        if not text:
            return _client_error_envelope(tool, f"unsupported MCP content: {type(first).__name__}", "command_failed")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return _client_error_envelope(tool, f"non-json response: {text[:200]}", "command_failed")
        if isinstance(parsed, dict):
            return _build_envelope(tool, parsed)
        return _client_error_envelope(tool, "MCP response is not an object", "command_failed")


__all__ = [
    "MODE_DISABLED",
    "MODE_LOCAL",
    "MODE_REAL",
    "KylinsecMCPClient",
    "is_mcp_sdk_installed",
]
