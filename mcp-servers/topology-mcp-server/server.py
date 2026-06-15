"""topology-mcp-server (FastMCP protocol layer).

This module is intentionally thin: every tool/resource simply forwards to a
function in :mod:`topology_service`. All business logic, error handling and
data representation lives in that module.

Run modes:
    python server.py        Start the MCP server over stdio.

Tests live in ``test_topology_service.py`` and exercise the service module
directly without depending on the ``mcp`` package.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

import topology_service as ts
from topology_service import AssetNotFoundError, TopologyError

logger = logging.getLogger("topology-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# Soft import: allow this file to load even when the ``mcp`` package is not
# yet installed. Tests do not need it; only ``main()`` requires it.
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("topology-mcp-server")
    _MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Exception | None = None
except Exception as exc:

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
# Unified response helpers.
# ---------------------------------------------------------------------------


def _ok(data: Any, message: str = "ok") -> dict[str, Any]:
    """Build the unified success envelope."""
    return {"success": True, "data": data, "message": message}


def _err(message: str) -> dict[str, Any]:
    """Build the unified failure envelope."""
    return {"success": False, "data": None, "message": message}


# ---------------------------------------------------------------------------
# MCP tools (thin wrappers around topology_service).
# ---------------------------------------------------------------------------


@mcp.tool()
def get_asset_info(ip_or_asset_id: str) -> dict[str, Any]:
    """Look up an asset by ``asset_id``, IP or name."""
    asset = ts.find_asset(ip_or_asset_id)
    if asset is None:
        return _err(f"asset not found: {ip_or_asset_id}")
    return _ok(asset, "asset resolved")


@mcp.tool()
def get_neighbors(ip_or_asset_id: str) -> dict[str, Any]:
    """List all directly-connected neighbors and the edges to them."""
    try:
        return _ok(ts.get_neighbors(ip_or_asset_id), "neighbors resolved")
    except AssetNotFoundError as exc:
        return _err(str(exc))


@mcp.tool()
def get_critical_assets() -> dict[str, Any]:
    """List assets with criticality HIGH or CRITICAL."""
    data = ts.get_critical_assets()
    return _ok(data, f"{data['count']} critical asset(s) listed")


@mcp.tool()
def find_paths(source: str, target: str, max_depth: int = 4) -> dict[str, Any]:
    """Enumerate allowed paths from ``source`` to ``target``."""
    try:
        data = ts.find_paths(source, target, max_depth)
        return _ok(data, f"{data['path_count']} path(s) found")
    except AssetNotFoundError as exc:
        return _err(str(exc))
    except ValueError as exc:
        return _err(str(exc))


@mcp.tool()
def check_connectivity(source: str, target: str) -> dict[str, Any]:
    """Check whether ``source`` can reach ``target`` within 4 hops."""
    try:
        data = ts.check_connectivity(source, target)
    except AssetNotFoundError as exc:
        return _err(str(exc))
    msg = "connectivity confirmed" if data["connected"] else "no allowed path within depth 4"
    return _ok(data, msg)


@mcp.tool()
def evaluate_strategy_impact(strategy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the topology impact of a DefenseStrategy-shaped dict."""
    try:
        data = ts.evaluate_strategy_impact(strategy)
    except (TypeError, TopologyError) as exc:
        return _err(str(exc))
    return _ok(data, f"impact evaluated as {data['impact_level']}")


# ---------------------------------------------------------------------------
# MCP resources.
# ---------------------------------------------------------------------------


@mcp.resource("topology://network", mime_type="application/json")
def res_network() -> str:
    """Full topology document (zones + assets + edges + metadata)."""
    return json.dumps(ts.get_topology(), ensure_ascii=False, indent=2)


@mcp.resource("topology://assets", mime_type="application/json")
def res_assets() -> str:
    """All assets in the topology."""
    return json.dumps(ts.get_topology().get("assets", []), ensure_ascii=False, indent=2)


@mcp.resource("topology://critical-assets", mime_type="application/json")
def res_critical_assets() -> str:
    """Assets with criticality HIGH or CRITICAL."""
    return json.dumps(
        ts.get_critical_assets()["assets"], ensure_ascii=False, indent=2
    )


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server over stdio."""
    if not _MCP_AVAILABLE:
        raise RuntimeError(
            "mcp package is not installed; run "
            f"`pip install -r requirements.txt` first. Original error: {_MCP_IMPORT_ERROR!r}"
        )
    topo = ts.get_topology()
    logger.info(
        "Starting topology-mcp-server with %d assets, %d edges",
        len(topo.get("assets", [])),
        len(topo.get("edges", [])),
    )
    mcp.run()


if __name__ == "__main__":
    main()
