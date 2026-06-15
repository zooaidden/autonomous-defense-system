"""Client adapter for ``policy-mcp-server``.

This module mirrors :mod:`agent_brain.integrations.mcp_client` (which adapts
``topology-mcp-server``) and exposes the four policy/impact MCP tools to the
rest of the system without forcing a hard dependency on the official
``mcp`` package.

Three working modes are supported (in priority order):

    1. ``disabled``: every method returns the canonical disabled envelope
       ``{"success": False, "data": None, "message": "..."}`` so that callers
       can transparently fall back to local-only logic. This is the default
       unless ``ENABLE_MCP=true`` is exported.

    2. ``local``: load ``policy-mcp-server/policy_service.py`` directly via
       ``importlib`` and call the pure functions in-process. Zero deps,
       zero startup cost; ideal for unit tests and CI.

    3. ``real``: spawn ``server.py`` over stdio and talk to it through the
       official MCP Python SDK ``ClientSession``. Requires ``mcp`` package
       to be installed. Used in staging / production debugging.

Environment variables (override constructor args):

    ENABLE_MCP                  Enable MCP at all (default: false).
    MCP_POLICY_MODE             ``local`` or ``real`` (default: ``local``).
    POLICY_MCP_SERVER_PATH      Absolute / relative path to
                                ``mcp-servers/policy-mcp-server``. Defaults
                                to the in-repo location.
    MCP_PYTHON_EXECUTABLE       Interpreter used to spawn ``server.py`` in
                                real mode (default: ``sys.executable``).
    MCP_REQUEST_TIMEOUT_S       Per-call timeout in real mode (default 10s).

All public methods return the unified envelope::

    {"success": true,  "data": ..., "message": "..."}
    {"success": false, "data": null, "message": "..."}
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

# __file__ -> .../agent-brain/src/agent_brain/integrations/policy_client.py
# parents[4] -> autonomous-defense-system/
_AGENT_BRAIN_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_SERVER_PATH = _AGENT_BRAIN_ROOT / "mcp-servers" / "policy-mcp-server"

# Mode constants (kept as lower-case strings for env-var ergonomics)
MODE_DISABLED = "disabled"
MODE_LOCAL = "local"
MODE_REAL = "real"

# Method-name to MCP tool-name map. Today they happen to match 1:1, but
# keeping a registry lets us decouple wire names from Python identifiers.
_TOOL_NAMES = {
    "validate_strategy": "validate_strategy",
    "check_business_constraints": "check_business_constraints",
    "require_human_approval": "require_human_approval",
    "suggest_safer_strategy": "suggest_safer_strategy",
}


# ---------------------------------------------------------------------------
# Soft import of the official MCP SDK. Local / disabled modes must keep
# working even if the package is missing.
# ---------------------------------------------------------------------------

try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore

    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # ImportError or anything else is treated as unavailable
    _MCP_AVAILABLE = False
    _MCP_IMPORT_ERROR = _exc
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean env var: accepts 1 / true / yes / on (case-insensitive)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _ok(data: Any, message: str = "ok") -> dict[str, Any]:
    """Build the canonical success envelope."""
    return {"success": True, "data": data, "message": message}


def _err(message: str) -> dict[str, Any]:
    """Build the canonical failure envelope."""
    return {"success": False, "data": None, "message": message}


def _resolve_mode(enabled: bool, mode_hint: str | None) -> str:
    """Collapse ``(enabled, mode_hint)`` into a single mode constant."""
    if not enabled:
        return MODE_DISABLED
    chosen = (mode_hint or MODE_LOCAL).strip().lower()
    if chosen not in (MODE_LOCAL, MODE_REAL):
        # Unknown values fall back to ``local`` so callers still get a
        # functional client instead of an error envelope.
        logger.warning("unknown MCP_POLICY_MODE=%r, falling back to 'local'", chosen)
        return MODE_LOCAL
    return chosen


# ---------------------------------------------------------------------------
# PolicyMCPClient
# ---------------------------------------------------------------------------


class PolicyMCPClient:
    """Unified client for ``policy-mcp-server``.

    Usage::

        # 1) Ad-hoc one-shot call
        async def demo():
            client = PolicyMCPClient()  # reads env vars
            try:
                res = await client.validate_strategy(strategy)
            finally:
                await client.aclose()

        # 2) Recommended: lifecycle managed by ``async with``
        async with PolicyMCPClient() as client:
            res = await client.validate_strategy(strategy)

    All constructor arguments are optional; missing values are pulled from
    environment variables, then from safe built-in defaults.
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
        # 1) Enable flag: explicit arg > env var > false.
        self._enabled = (
            enabled if enabled is not None else _env_bool("ENABLE_MCP", default=False)
        )
        # 2) Concrete mode (disabled / local / real).
        self._mode = _resolve_mode(
            self._enabled,
            mode if mode is not None else os.environ.get("MCP_POLICY_MODE"),
        )
        # 3) policy-mcp-server directory.
        path_str = (
            str(server_path)
            if server_path is not None
            else os.environ.get("POLICY_MCP_SERVER_PATH")
        )
        self._server_path: Path = (
            Path(path_str).expanduser().resolve()
            if path_str
            else _DEFAULT_SERVER_PATH
        )
        # 4) Python interpreter used to spawn server.py in real mode.
        self._python_executable = (
            python_executable
            or os.environ.get("MCP_PYTHON_EXECUTABLE")
            or sys.executable
        )
        # 5) Per-call timeout in real mode.
        if request_timeout is not None:
            self._timeout = float(request_timeout)
        else:
            try:
                self._timeout = float(os.environ.get("MCP_REQUEST_TIMEOUT_S", "10"))
            except ValueError:
                self._timeout = 10.0

        # Lazily-loaded local module cache.
        self._policy_service: ModuleType | None = None
        # Real-mode async lifecycle handles.
        self._exit_stack: AsyncExitStack | None = None
        self._session: Any = None

        logger.info(
            "PolicyMCPClient initialized: enabled=%s mode=%s server_path=%s",
            self._enabled,
            self._mode,
            self._server_path,
        )

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether MCP is enabled at all (disabled mode short-circuits every call)."""
        return self._enabled

    @property
    def mode(self) -> str:
        """Currently effective mode: ``disabled`` / ``local`` / ``real``."""
        return self._mode

    @property
    def server_path(self) -> Path:
        """Path to the policy-mcp-server directory."""
        return self._server_path

    # ------------------------------------------------------------------
    # Async lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "PolicyMCPClient":
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
                logger.warning("error closing policy MCP session: %s", exc)
            finally:
                self._exit_stack = None
                self._session = None

    # ------------------------------------------------------------------
    # Public tool methods (1-to-1 with policy-mcp-server tools)
    # ------------------------------------------------------------------

    async def validate_strategy(self, strategy: dict[str, Any]) -> dict[str, Any]:
        """Run the full 7-rule policy validation."""
        return await self._dispatch("validate_strategy", {"strategy": strategy})

    async def check_business_constraints(
        self, strategy: dict[str, Any]
    ) -> dict[str, Any]:
        """Run the business-impact subset of the rules."""
        return await self._dispatch("check_business_constraints", {"strategy": strategy})

    async def require_human_approval(
        self, strategy: dict[str, Any]
    ) -> dict[str, Any]:
        """Decide whether the strategy must be escalated for human approval."""
        return await self._dispatch("require_human_approval", {"strategy": strategy})

    async def suggest_safer_strategy(
        self, strategy: dict[str, Any]
    ) -> dict[str, Any]:
        """Produce structured remediation patches for any rule violations."""
        return await self._dispatch("suggest_safer_strategy", {"strategy": strategy})

    # ------------------------------------------------------------------
    # Dispatcher: unified disabled / local / real handling
    # ------------------------------------------------------------------

    async def _dispatch(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call to the active mode and never raise to callers."""
        if self._mode == MODE_DISABLED:
            return _err("MCP integration is disabled (ENABLE_MCP=false)")

        try:
            if self._mode == MODE_LOCAL:
                return await self._call_local(tool, arguments)
            if self._mode == MODE_REAL:
                return await self._call_real(tool, arguments)
            # Unreachable in practice: ``_resolve_mode`` already collapses values.
            return _err(f"unsupported MCP mode: {self._mode}")
        except Exception as exc:  # last-resort guard: wrap into failure envelope
            logger.exception("policy MCP tool '%s' failed", tool)
            return _err(f"{tool} failed: {exc.__class__.__name__}: {exc}")

    # ------------------------------------------------------------------
    # Local mode: in-process call into policy_service.py
    # ------------------------------------------------------------------

    async def _call_local(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call ``policy_service.<tool>`` directly. CPU-bound and fast."""
        ps = self._load_policy_service()
        strategy = arguments.get("strategy")

        if tool == "validate_strategy":
            try:
                data = ps.validate_strategy(strategy)
            except (TypeError, ps.PolicyServiceError) as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, _summary(data, tool))

        if tool == "check_business_constraints":
            try:
                data = ps.check_business_constraints(strategy)
            except (TypeError, ps.PolicyServiceError) as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, _summary(data, tool))

        if tool == "require_human_approval":
            try:
                data = ps.require_human_approval(strategy)
            except (TypeError, ps.PolicyServiceError) as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, _summary(data, tool))

        if tool == "suggest_safer_strategy":
            try:
                data = ps.suggest_safer_strategy(strategy)
            except (TypeError, ps.PolicyServiceError) as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, _summary(data, tool))

        return _err(f"unknown local tool: {tool}")

    def _load_policy_service(self) -> ModuleType:
        """Load policy_service.py via importlib without polluting sys.path."""
        if self._policy_service is not None:
            return self._policy_service
        if not self._server_path.exists():
            raise FileNotFoundError(
                f"policy mcp server path does not exist: {self._server_path}"
            )
        module_path = self._server_path / "policy_service.py"
        if not module_path.exists():
            raise FileNotFoundError(
                f"policy_service.py not found at: {module_path}"
            )
        spec = importlib.util.spec_from_file_location(
            "agent_brain_policy_service_local", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build module spec for: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._policy_service = module
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
        session = await self._ensure_real_session()
        tool_name = _TOOL_NAMES.get(tool, tool)
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool_name, arguments),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return _err(f"MCP tool '{tool_name}' timed out after {self._timeout}s")
        return self._parse_tool_result(result)

    async def _ensure_real_session(self) -> Any:
        """Lazily build the stdio session bound to ``self._exit_stack``.

        Tests may pre-inject ``self._session`` to bypass the subprocess; the
        ``mcp`` package is only required when we actually need to spawn it.
        """
        if self._session is not None:
            return self._session
        if not _MCP_AVAILABLE:
            raise RuntimeError(
                "mcp package not installed; install via "
                f"`pip install -e .[mcp]` or set ENABLE_MCP=false. "
                f"Original error: {_MCP_IMPORT_ERROR!r}"
            )
        server_script = self._server_path / "server.py"
        if not server_script.exists():
            raise FileNotFoundError(f"server.py not found at: {server_script}")

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
    def _parse_tool_result(result: Any) -> dict[str, Any]:
        """Decode a ``CallToolResult`` back into ``{success, data, message}``."""
        # 1) Error result: extract any embedded text content.
        if getattr(result, "isError", False):
            msgs: list[str] = []
            for item in getattr(result, "content", []) or []:
                text = getattr(item, "text", None)
                if text:
                    msgs.append(str(text))
            return _err("; ".join(msgs) or "tool returned error")

        # 2) Prefer MCP >=1.2 structured output if present.
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            if "success" in structured and "data" in structured:
                return structured
            return _ok(structured)

        # 3) Fall back to ``content[0].text``.
        content = getattr(result, "content", []) or []
        if not content:
            return _ok(None, "empty response")
        first = content[0]
        text = getattr(first, "text", None)
        if not text:
            return _err(f"unsupported MCP content type: {type(first).__name__}")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return _err(f"non-json response: {text[:200]}")
        if isinstance(parsed, dict) and "success" in parsed and "data" in parsed:
            return parsed
        return _ok(parsed)


def _summary(data: dict[str, Any], op: str) -> str:
    """Build a one-line message that mirrors what server.py emits."""
    v = len(data.get("violations") or [])
    w = len(data.get("warnings") or [])
    return (
        f"{op}: valid={data.get('valid', False)}, "
        f"violations={v}, warnings={w}, "
        f"requires_human_approval={data.get('requires_human_approval', False)}"
    )


__all__ = [
    "MODE_DISABLED",
    "MODE_LOCAL",
    "MODE_REAL",
    "PolicyMCPClient",
]
