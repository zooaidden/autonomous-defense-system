"""policy-mcp-server（FastMCP 协议薄壳）。

本文件刻意做得很薄：每个 MCP tool 都只是把 :mod:`policy_service` 中的
同名公共函数转发一下，并把异常 / 返回值统一封装成
``{success, data, message}`` 三元组。所有业务逻辑、规则定义、违规建议
都放在 ``policy_service.py`` 中，便于直接做单元测试，无需安装 mcp。

启动方式：
    python server.py

测试位于 ``test_policy_service.py``，直接 import ``policy_service``，不依赖 mcp。
"""
from __future__ import annotations

import logging
from typing import Any

import policy_service as ps
from policy_service import PolicyServiceError

logger = logging.getLogger("policy-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# 软导入：未安装 mcp 包时也允许本文件被加载（测试场景）
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("policy-mcp-server")
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
# 统一返回信封
# ---------------------------------------------------------------------------


def _ok(data: Any, message: str = "ok") -> dict[str, Any]:
    """构造统一的成功信封。"""
    return {"success": True, "data": data, "message": message}


def _err(message: str) -> dict[str, Any]:
    """构造统一的失败信封。"""
    return {"success": False, "data": None, "message": message}


def _summary_message(data: dict[str, Any], op: str) -> str:
    """根据 result 字段生成简短的 message，便于日志查看。"""
    v = len(data.get("violations") or [])
    w = len(data.get("warnings") or [])
    return (
        f"{op}: valid={data.get('valid', False)}, "
        f"violations={v}, warnings={w}, "
        f"requires_human_approval={data.get('requires_human_approval', False)}"
    )


# ---------------------------------------------------------------------------
# MCP tools（业务逻辑全部转发到 policy_service）
# ---------------------------------------------------------------------------


@mcp.tool()
def validate_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    """运行全部 7 条规则做完整合规校验。"""
    try:
        data = ps.validate_strategy(strategy)
    except (TypeError, PolicyServiceError) as exc:
        return _err(str(exc))
    return _ok(data, _summary_message(data, "validate_strategy"))


@mcp.tool()
def check_business_constraints(strategy: dict[str, Any]) -> dict[str, Any]:
    """专注业务影响相关的规则（关键资产/生产路径/过宽阻断）。"""
    try:
        data = ps.check_business_constraints(strategy)
    except (TypeError, PolicyServiceError) as exc:
        return _err(str(exc))
    return _ok(data, _summary_message(data, "check_business_constraints"))


@mcp.tool()
def require_human_approval(strategy: dict[str, Any]) -> dict[str, Any]:
    """判定该策略是否需要走人工审批。"""
    try:
        data = ps.require_human_approval(strategy)
    except (TypeError, PolicyServiceError) as exc:
        return _err(str(exc))
    return _ok(data, _summary_message(data, "require_human_approval"))


@mcp.tool()
def suggest_safer_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    """根据违规情况返回可落地的安全策略修复建议。"""
    try:
        data = ps.suggest_safer_strategy(strategy)
    except (TypeError, PolicyServiceError) as exc:
        return _err(str(exc))
    return _ok(data, _summary_message(data, "suggest_safer_strategy"))


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
    rules = ps.get_rules()
    logger.info(
        "Starting policy-mcp-server with %d rules, %d critical assets, %d production paths",
        len(rules.get("rules", [])),
        len(rules.get("critical_assets", [])),
        len(rules.get("production_paths", [])),
    )
    mcp.run()


if __name__ == "__main__":
    main()
