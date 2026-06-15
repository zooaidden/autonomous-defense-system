"""actuator-mcp-server（FastMCP 协议薄壳）。

本文件刻意做得很薄：每个 MCP tool 都把 :mod:`actuator_client` 中
``ActuatorClient`` 同名方法的结果转发出去，再统一封装成
``{success, data, message}`` 三元组。HTTP 调用、安全检查、mock 模式
全部在 ``actuator_client.py`` 中完成，便于直接做单元测试，无需安装 mcp。

启动方式::

    python server.py

环境变量::

    ACTUATOR_BASE_URL        actuator-service 根地址，默认 http://localhost:8081
    ACTUATOR_MODE            real / mock，默认 real
    ACTUATOR_HTTP_TIMEOUT    单次 HTTP 调用超时秒数，默认 5
"""
from __future__ import annotations

import logging
from typing import Any

from actuator_client import ActuatorClient

logger = logging.getLogger("actuator-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# 软导入：未安装 mcp 包时也允许本文件被加载（测试场景）
# ---------------------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("actuator-mcp-server")
    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as exc:

    class _NoOpMCP:
        """在 mcp 未安装时做占位用的空实现。"""

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
# 单例 ActuatorClient：进程级共享，避免每次工具调用重复读环境变量
# ---------------------------------------------------------------------------

_client: ActuatorClient | None = None


def _get_client() -> ActuatorClient:
    """惰性初始化业务 client。测试可以直接 monkeypatch 该函数。"""
    global _client
    if _client is None:
        _client = ActuatorClient()
    return _client


def _err(message: str) -> dict[str, Any]:
    """业务异常都统一包装成失败信封，避免穿透到协议层。"""
    return {"success": False, "data": None, "message": message}


# ---------------------------------------------------------------------------
# MCP tools：与 ActuatorClient 一一对应
# ---------------------------------------------------------------------------


@mcp.tool()
def execute_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    """下发执行最终策略。

    在调用 actuator-service 之前会做 4 项安全检查：

    1. ``human_approval_required`` 为 true 时拒绝自动执行；
    2. ``status`` 不是 ``approved_for_execution`` 时拒绝执行；
    3. 缺失 ``rollback_plan`` 时：高风险动作拒绝，普通动作给 warning；
    4. 缺失 ``ttl`` / ``ttl_minutes`` 时：高风险动作拒绝，普通动作给 warning。

    任一检查失败时不会触发 HTTP 调用，``data.pre_check`` 中说明被拒原因。
    成功时 ``data`` 含 actuator-service 返回的 ExecutionRecord。
    """
    try:
        return _get_client().execute_strategy(strategy)
    except Exception as exc:  # 兜底：所有异常都不允许穿透到 MCP 协议层
        logger.exception("execute_strategy raised unexpected error")
        return _err(f"execute_strategy raised: {exc.__class__.__name__}: {exc}")


@mcp.tool()
def rollback_strategy(strategy_id: str) -> dict[str, Any]:
    """对指定策略触发回滚。"""
    try:
        return _get_client().rollback_strategy(strategy_id)
    except Exception as exc:
        logger.exception("rollback_strategy raised unexpected error")
        return _err(f"rollback_strategy raised: {exc.__class__.__name__}: {exc}")


@mcp.tool()
def get_execution_status(execution_id: str) -> dict[str, Any]:
    """查询单条执行记录的最新状态。"""
    try:
        return _get_client().get_execution_status(execution_id)
    except Exception as exc:
        logger.exception("get_execution_status raised unexpected error")
        return _err(f"get_execution_status raised: {exc.__class__.__name__}: {exc}")


@mcp.tool()
def list_executions(limit: int = 20) -> dict[str, Any]:
    """列出最近的执行记录；本地按 limit 裁剪。"""
    try:
        return _get_client().list_executions(limit)
    except Exception as exc:
        logger.exception("list_executions raised unexpected error")
        return _err(f"list_executions raised: {exc.__class__.__name__}: {exc}")


# ---------------------------------------------------------------------------
# 程序入口
# ---------------------------------------------------------------------------


def main() -> None:
    """以 stdio 协议启动 MCP server。"""
    if not _MCP_AVAILABLE:
        raise RuntimeError(
            "mcp package is not installed; run "
            f"`pip install -r requirements.txt` first. Original error: {_MCP_IMPORT_ERROR!r}"
        )
    client = _get_client()
    logger.info(
        "Starting actuator-mcp-server: base_url=%s mode=%s timeout=%.1fs",
        client.base_url,
        client.mode,
        client.timeout,
    )
    mcp.run()


if __name__ == "__main__":
    main()
