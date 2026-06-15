"""topology-mcp-server 的客户端适配层。

本模块只负责"拨号"，不修改任何 Agent 工作流，让上层逻辑可以独立选择
何时引入 MCP 调用。

支持三种工作模式（按优先级从高到低）：

    1. ``disabled``：完全关闭。所有方法返回 ``{success=False, message="..."}``
       的禁用响应，方便上层 fallback。这是默认模式（除非显式打开 ENABLE_MCP）。

    2. ``local``：不启动子进程，直接通过 ``importlib`` 加载
       ``mcp-servers/topology-mcp-server/topology_service.py``，
       在同进程内调用其纯函数。优点：零依赖、零启动开销，便于单元测试。

    3. ``real``：以 stdio 协议拉起 ``server.py`` 子进程，通过官方
       MCP Python SDK 的 ``ClientSession`` 调用工具。需要安装 ``mcp`` 包，
       通常用于 staging / 生产联调。

环境变量：

    ENABLE_MCP                 是否启用 MCP（true/false，默认 false）
    MCP_TOPOLOGY_MODE          local 或 real（默认 local）
    TOPOLOGY_MCP_SERVER_PATH   topology-mcp-server 目录绝对/相对路径
                               （默认指向同仓库下的 mcp-servers/topology-mcp-server）
    MCP_PYTHON_EXECUTABLE      real 模式下用来启动 server.py 的解释器
                               （默认 sys.executable）
    MCP_REQUEST_TIMEOUT_S      real 模式单次工具调用超时（默认 10 秒）

公共返回格式（所有方法）::

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
# 默认路径与常量
# ---------------------------------------------------------------------------

# __file__: .../agent-brain/src/agent_brain/integrations/mcp_client.py
# parents[4] -> autonomous-defense-system/
_AGENT_BRAIN_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_SERVER_PATH = _AGENT_BRAIN_ROOT / "mcp-servers" / "topology-mcp-server"

# 模式枚举（字符串常量，足够轻量）
MODE_DISABLED = "disabled"
MODE_LOCAL = "local"
MODE_REAL = "real"

# 工具名映射：方法名 -> MCP 工具名
_TOOL_NAMES = {
    "get_asset_info": "get_asset_info",
    "get_neighbors": "get_neighbors",
    "get_critical_assets": "get_critical_assets",
    "find_paths": "find_paths",
    "check_connectivity": "check_connectivity",
    "evaluate_strategy_impact": "evaluate_strategy_impact",
}


# ---------------------------------------------------------------------------
# 软导入官方 MCP SDK：未安装时仍允许 disabled / local 模式工作
# ---------------------------------------------------------------------------

try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore

    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # ImportError 或其它任何异常都视为不可用
    _MCP_AVAILABLE = False
    _MCP_IMPORT_ERROR = _exc
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool = False) -> bool:
    """解析布尔型环境变量；接受 1/true/yes/on（大小写不敏感）。"""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _ok(data: Any, message: str = "ok") -> dict[str, Any]:
    """统一的成功响应。"""
    return {"success": True, "data": data, "message": message}


def _err(message: str) -> dict[str, Any]:
    """统一的失败响应。"""
    return {"success": False, "data": None, "message": message}


def _resolve_mode(enabled: bool, mode_hint: str | None) -> str:
    """把 (enabled, mode_hint) 收敛成最终模式字符串。"""
    if not enabled:
        return MODE_DISABLED
    chosen = (mode_hint or MODE_LOCAL).strip().lower()
    if chosen not in (MODE_LOCAL, MODE_REAL):
        # 不认识的字符串：默认退回 local，保证可用
        logger.warning("unknown MCP_TOPOLOGY_MODE=%r, falling back to 'local'", chosen)
        return MODE_LOCAL
    return chosen


# ---------------------------------------------------------------------------
# TopologyMCPClient
# ---------------------------------------------------------------------------


class TopologyMCPClient:
    """topology-mcp-server 的统一客户端。

    使用方式::

        # 1) 同步上下文里临时调用一次（适合脚本/测试）
        async def demo():
            client = TopologyMCPClient()  # 读取环境变量
            try:
                res = await client.get_asset_info("app-payment-01")
            finally:
                await client.aclose()

        # 2) 推荐：用 async with 管理生命周期
        async with TopologyMCPClient() as client:
            res = await client.get_critical_assets()

    参数全部可选，未指定时从环境变量读取；环境变量未设置时使用安全默认。
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
        # 1) 是否启用：构造参数 > 环境变量 > 默认 false
        self._enabled = (
            enabled if enabled is not None else _env_bool("ENABLE_MCP", default=False)
        )
        # 2) 模式：local / real / disabled（disabled 是 enabled=false 的同义）
        self._mode = _resolve_mode(
            self._enabled,
            mode if mode is not None else os.environ.get("MCP_TOPOLOGY_MODE"),
        )
        # 3) topology-mcp-server 目录路径
        path_str = (
            str(server_path)
            if server_path is not None
            else os.environ.get("TOPOLOGY_MCP_SERVER_PATH")
        )
        self._server_path: Path = (
            Path(path_str).expanduser().resolve()
            if path_str
            else _DEFAULT_SERVER_PATH
        )
        # 4) real 模式启动 server.py 用的 Python 解释器
        self._python_executable = (
            python_executable
            or os.environ.get("MCP_PYTHON_EXECUTABLE")
            or sys.executable
        )
        # 5) real 模式单次工具调用超时
        if request_timeout is not None:
            self._timeout = float(request_timeout)
        else:
            try:
                self._timeout = float(os.environ.get("MCP_REQUEST_TIMEOUT_S", "10"))
            except ValueError:
                self._timeout = 10.0

        # local 模式的拓扑服务模块缓存
        self._topology_service: ModuleType | None = None
        # real 模式的会话 + 异步上下文栈
        self._exit_stack: AsyncExitStack | None = None
        self._session: Any = None  # ClientSession，懒加载

        logger.info(
            "TopologyMCPClient initialized: enabled=%s mode=%s server_path=%s",
            self._enabled,
            self._mode,
            self._server_path,
        )

    # ------------------------------------------------------------------
    # 只读属性
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """是否启用 MCP 调用（disabled 时所有方法返回 disabled 响应）。"""
        return self._enabled

    @property
    def mode(self) -> str:
        """当前生效的模式：disabled / local / real。"""
        return self._mode

    @property
    def server_path(self) -> Path:
        """topology-mcp-server 目录路径。"""
        return self._server_path

    # ------------------------------------------------------------------
    # 异步上下文管理
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "TopologyMCPClient":
        # real 模式下提前建立连接；其它模式不需要
        if self._mode == MODE_REAL:
            await self._ensure_real_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """关闭底层 stdio 子进程与会话；幂等。"""
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception as exc:  # 关闭失败不应阻塞调用方
                logger.warning("error closing MCP session: %s", exc)
            finally:
                self._exit_stack = None
                self._session = None

    # ------------------------------------------------------------------
    # 公共工具方法（与 MCP server 工具一一对应）
    # ------------------------------------------------------------------

    async def get_asset_info(self, ip_or_asset_id: str) -> dict[str, Any]:
        """根据 asset_id / IP / name 查询资产详情。"""
        return await self._dispatch("get_asset_info", {"ip_or_asset_id": ip_or_asset_id})

    async def get_neighbors(self, ip_or_asset_id: str) -> dict[str, Any]:
        """获取与指定资产直连的全部邻居。"""
        return await self._dispatch("get_neighbors", {"ip_or_asset_id": ip_or_asset_id})

    async def get_critical_assets(self) -> dict[str, Any]:
        """列出 criticality=HIGH/CRITICAL 的资产。"""
        return await self._dispatch("get_critical_assets", {})

    async def find_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 4,
    ) -> dict[str, Any]:
        """枚举 source -> target 的所有允许路径。"""
        return await self._dispatch(
            "find_paths",
            {"source": source, "target": target, "max_depth": max_depth},
        )

    async def check_connectivity(self, source: str, target: str) -> dict[str, Any]:
        """检查 source 到 target 是否可达（最大 4 跳）。"""
        return await self._dispatch(
            "check_connectivity",
            {"source": source, "target": target},
        )

    async def evaluate_strategy_impact(
        self,
        strategy: dict[str, Any],
    ) -> dict[str, Any]:
        """评估一条 DefenseStrategy 对网络拓扑的影响面。"""
        return await self._dispatch("evaluate_strategy_impact", {"strategy": strategy})

    # ------------------------------------------------------------------
    # 派发器：统一处理 disabled / local / real 三种模式
    # ------------------------------------------------------------------

    async def _dispatch(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """根据当前模式分派到对应的执行路径，并保证异常不外泄。"""
        if self._mode == MODE_DISABLED:
            return _err("MCP integration is disabled (ENABLE_MCP=false)")

        try:
            if self._mode == MODE_LOCAL:
                return await self._call_local(tool, arguments)
            if self._mode == MODE_REAL:
                return await self._call_real(tool, arguments)
            # 理论上不会走到这里，_resolve_mode 已经收敛过
            return _err(f"unsupported MCP mode: {self._mode}")
        except Exception as exc:  # 兜底：任何异常都包装成失败响应
            logger.exception("MCP tool '%s' failed", tool)
            return _err(f"{tool} failed: {exc.__class__.__name__}: {exc}")

    # ------------------------------------------------------------------
    # local 模式：直接调用 topology_service 的纯函数
    # ------------------------------------------------------------------

    async def _call_local(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """在同进程中调用 topology_service.<tool>。"""
        ts = self._load_topology_service()

        # 这些函数都是同步 CPU-bound，简单直调即可；如果以后变重，
        # 可以改成 asyncio.to_thread 包一层。
        if tool == "get_asset_info":
            asset = ts.find_asset(arguments["ip_or_asset_id"])
            if asset is None:
                return _err(f"asset not found: {arguments['ip_or_asset_id']}")
            return _ok(asset, "asset resolved")

        if tool == "get_neighbors":
            try:
                data = ts.get_neighbors(arguments["ip_or_asset_id"])
            except ts.AssetNotFoundError as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, "neighbors resolved")

        if tool == "get_critical_assets":
            data = ts.get_critical_assets()
            return _ok(data, f"{data['count']} critical asset(s) listed")

        if tool == "find_paths":
            try:
                data = ts.find_paths(
                    arguments["source"],
                    arguments["target"],
                    int(arguments.get("max_depth", 4)),
                )
            except ts.AssetNotFoundError as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            except ValueError as exc:
                return _err(str(exc))
            return _ok(data, f"{data['path_count']} path(s) found")

        if tool == "check_connectivity":
            try:
                data = ts.check_connectivity(arguments["source"], arguments["target"])
            except ts.AssetNotFoundError as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            msg = (
                "connectivity confirmed"
                if data["connected"]
                else "no allowed path within depth 4"
            )
            return _ok(data, msg)

        if tool == "evaluate_strategy_impact":
            try:
                data = ts.evaluate_strategy_impact(arguments["strategy"])
            except (TypeError, ts.TopologyError) as exc:  # type: ignore[attr-defined]
                return _err(str(exc))
            return _ok(data, f"impact evaluated as {data['impact_level']}")

        return _err(f"unknown local tool: {tool}")

    def _load_topology_service(self) -> ModuleType:
        """通过 importlib 直接加载 topology_service.py，避免污染 sys.path。"""
        if self._topology_service is not None:
            return self._topology_service
        if not self._server_path.exists():
            raise FileNotFoundError(
                f"topology mcp server path does not exist: {self._server_path}"
            )
        module_path = self._server_path / "topology_service.py"
        if not module_path.exists():
            raise FileNotFoundError(
                f"topology_service.py not found at: {module_path}"
            )
        spec = importlib.util.spec_from_file_location(
            "agent_brain_topology_service_local", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build module spec for: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._topology_service = module
        return module

    # ------------------------------------------------------------------
    # real 模式：通过 MCP stdio 拉起 server.py 子进程
    # ------------------------------------------------------------------

    async def _call_real(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """通过 MCP ClientSession.call_tool 调用，并解析返回为统一信封。

        注意：mcp 包可用性的检查放在 ``_ensure_real_session`` 里，这样
        如果调用方预先注入了 ``_session``（例如测试场景），可以跳过子进程
        启动直接复用现有会话。
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
        """惰性建立 stdio 子进程 + ClientSession，会话生命周期挂在 _exit_stack。

        如果调用方已经手动注入了 ``self._session``（例如单元测试中的伪造会话），
        就直接复用，不会再尝试拉起子进程，也不要求安装 ``mcp`` 包。
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
                # 父进程的 PATH/PYTHONPATH 默认会传递；不显式覆写
                env=None,
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception:
            # 若中途失败，及时回收已经进入的上下文
            await stack.aclose()
            raise

        self._exit_stack = stack
        self._session = session
        return session

    @staticmethod
    def _parse_tool_result(result: Any) -> dict[str, Any]:
        """把 MCP CallToolResult 解析回 {success, data, message} 信封。

        约定：topology-mcp-server 的工具本身就返回该信封并被 FastMCP 序列化为
        TextContent；这里把字符串还原为 dict。其它形态做兜底处理。
        """
        # 1) 错误结果：从 content 提取错误文本
        if getattr(result, "isError", False):
            msgs: list[str] = []
            for item in getattr(result, "content", []) or []:
                text = getattr(item, "text", None)
                if text:
                    msgs.append(str(text))
            return _err("; ".join(msgs) or "tool returned error")

        # 2) 优先使用 SDK 提供的结构化输出（structuredContent 字段，>=1.2 支持）
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            if "success" in structured and "data" in structured:
                return structured
            return _ok(structured)

        # 3) 退化到 content[0].text
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


__all__ = [
    "MODE_DISABLED",
    "MODE_LOCAL",
    "MODE_REAL",
    "TopologyMCPClient",
]
