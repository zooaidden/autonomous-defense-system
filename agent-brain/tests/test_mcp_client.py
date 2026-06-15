"""TopologyMCPClient 的单元测试。

只覆盖 disabled / local 两种模式。real 模式涉及子进程拉起 MCP server，
更适合放到端到端测试或人工冒烟脚本里，这里通过 monkeypatch 模拟一次会话
来验证响应解析逻辑，不实际启动子进程。

运行方式::

    cd autonomous-defense-system/agent-brain
    pytest -q tests/test_mcp_client.py
"""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agent_brain.integrations.mcp_client import (
    MODE_DISABLED,
    MODE_LOCAL,
    MODE_REAL,
    TopologyMCPClient,
)


# 一个最小拓扑，用于 local 模式从自定义 server_path 加载（避免依赖默认路径）
# parents[2] 指向 autonomous-defense-system/，与 test_policy_client.py 的算法保持一致
_FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "topology-mcp-server"
)


def _run(coro):
    """在同步测试里运行一个协程；避免引入 pytest-asyncio 依赖。"""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# disabled 模式
# ---------------------------------------------------------------------------


class DisabledModeTests(unittest.TestCase):
    """ENABLE_MCP=false 时所有方法都应该返回禁用响应。"""

    def test_default_constructor_is_disabled(self) -> None:
        # 不依赖环境变量，构造时显式关闭
        client = TopologyMCPClient(enabled=False)
        self.assertFalse(client.enabled)
        self.assertEqual(client.mode, MODE_DISABLED)

    def test_disabled_returns_failure_envelope(self) -> None:
        client = TopologyMCPClient(enabled=False)
        result = _run(client.get_critical_assets())
        self.assertEqual(result["success"], False)
        self.assertIsNone(result["data"])
        self.assertIn("disabled", result["message"].lower())

    def test_disabled_evaluate_strategy_impact(self) -> None:
        client = TopologyMCPClient(enabled=False)
        result = _run(
            client.evaluate_strategy_impact(
                {"strategyId": "x", "actions": [{"type": "ALERT_ONLY", "target": "x"}]}
            )
        )
        self.assertFalse(result["success"])
        self.assertIn("disabled", result["message"].lower())


# ---------------------------------------------------------------------------
# local 模式：真实读取 mcp-servers/topology-mcp-server/topology_service.py
# ---------------------------------------------------------------------------


class LocalModeTests(unittest.TestCase):
    """local 模式下应通过 importlib 调到 topology_service 的纯函数。"""

    def setUp(self) -> None:
        self.client = TopologyMCPClient(
            enabled=True,
            mode=MODE_LOCAL,
            server_path=_FIXTURE_SERVER_PATH,
        )

    def tearDown(self) -> None:
        _run(self.client.aclose())

    def test_mode_is_local(self) -> None:
        self.assertEqual(self.client.mode, MODE_LOCAL)
        self.assertTrue(self.client.enabled)

    def test_get_asset_info_existing(self) -> None:
        result = _run(self.client.get_asset_info("app-payment-01"))
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["asset_id"], "app-payment-01")
        self.assertEqual(result["data"]["criticality"], "CRITICAL")

    def test_get_asset_info_by_ip(self) -> None:
        result = _run(self.client.get_asset_info("10.30.1.10"))
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["asset_id"], "db-primary-01")

    def test_get_asset_info_missing(self) -> None:
        result = _run(self.client.get_asset_info("ghost-asset"))
        self.assertFalse(result["success"])
        self.assertIn("not found", result["message"])

    def test_get_neighbors_existing(self) -> None:
        result = _run(self.client.get_neighbors("dmz-api-01"))
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["data"]["neighbor_count"], 4)

    def test_get_neighbors_missing(self) -> None:
        result = _run(self.client.get_neighbors("ghost-asset"))
        self.assertFalse(result["success"])
        self.assertIn("not found", result["message"])

    def test_get_critical_assets(self) -> None:
        result = _run(self.client.get_critical_assets())
        self.assertTrue(result["success"])
        self.assertGreater(result["data"]["count"], 0)
        for asset in result["data"]["assets"]:
            self.assertIn(asset["criticality"].upper(), {"HIGH", "CRITICAL"})

    def test_find_paths_dmz_api_to_db_primary(self) -> None:
        result = _run(self.client.find_paths("dmz-api-01", "db-primary-01"))
        self.assertTrue(result["success"])
        self.assertGreater(result["data"]["path_count"], 0)
        for path in result["data"]["paths"]:
            self.assertEqual(path["nodes"][0], "dmz-api-01")
            self.assertEqual(path["nodes"][-1], "db-primary-01")

    def test_find_paths_invalid_depth(self) -> None:
        result = _run(self.client.find_paths("dmz-api-01", "db-primary-01", max_depth=0))
        self.assertFalse(result["success"])
        self.assertIn("max_depth", result["message"])

    def test_check_connectivity_connected(self) -> None:
        result = _run(self.client.check_connectivity("dmz-web-01", "db-primary-01"))
        self.assertTrue(result["success"])
        self.assertTrue(result["data"]["connected"])
        self.assertGreater(result["data"]["shortest_hops"], 1)

    def test_check_connectivity_reverse_not_connected(self) -> None:
        result = _run(self.client.check_connectivity("db-primary-01", "dmz-web-01"))
        self.assertTrue(result["success"])
        self.assertFalse(result["data"]["connected"])

    def test_evaluate_strategy_impact_critical(self) -> None:
        result = _run(
            self.client.evaluate_strategy_impact(
                {
                    "strategyId": "stg-payment",
                    "actions": [{"type": "ISOLATE_POD", "target": "app-payment-01"}],
                }
            )
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["impact_level"], "CRITICAL")
        path_types = {p["path_type"] for p in result["data"]["affected_paths"]}
        self.assertIn("DMZ_TO_DATABASE", path_types)

    def test_evaluate_strategy_impact_low(self) -> None:
        result = _run(
            self.client.evaluate_strategy_impact(
                {
                    "strategyId": "stg-waf",
                    "actions": [{"type": "APPLY_WAF_RULE", "target": "dmz-api-01"}],
                }
            )
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["impact_level"], "LOW")


# ---------------------------------------------------------------------------
# local 模式 + 错误的 server_path 应当稳健失败
# ---------------------------------------------------------------------------


class LocalModeBadPathTests(unittest.TestCase):
    def test_missing_server_path_returns_failure(self) -> None:
        client = TopologyMCPClient(
            enabled=True,
            mode=MODE_LOCAL,
            server_path="/nonexistent/path/to/topology-mcp-server",
        )
        result = _run(client.get_critical_assets())
        self.assertFalse(result["success"])
        # 错误信息应当至少提到路径不存在
        self.assertTrue(
            "does not exist" in result["message"]
            or "not found" in result["message"].lower(),
            msg=f"unexpected message: {result['message']}",
        )


# ---------------------------------------------------------------------------
# real 模式：通过 monkeypatch 模拟 ClientSession，验证返回解析逻辑
# ---------------------------------------------------------------------------


class _FakeTextContent:
    """模拟 mcp.types.TextContent。"""

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallToolResult:
    def __init__(
        self,
        text: str | None = None,
        structured=None,
        is_error: bool = False,
    ) -> None:
        self.isError = is_error
        self.structuredContent = structured
        self.content = [_FakeTextContent(text)] if text is not None else []


class RealModeParsingTests(unittest.TestCase):
    """real 模式不真正启动子进程，只验证 _parse_tool_result 与派发链路。"""

    def _client_with_fake_session(self, fake_result) -> TopologyMCPClient:
        client = TopologyMCPClient(
            enabled=True,
            mode=MODE_REAL,
            server_path=_FIXTURE_SERVER_PATH,
        )
        # 直接塞入一个伪造的 session，跳过真实的 stdio 拉起流程
        fake_session = MagicMock()

        async def _call_tool(name, arguments):
            return fake_result

        fake_session.call_tool = _call_tool
        client._session = fake_session  # type: ignore[attr-defined]
        return client

    def test_real_mode_parses_envelope_text(self) -> None:
        envelope = (
            '{"success": true, "data": {"asset_id": "app-payment-01"},'
            ' "message": "asset resolved"}'
        )
        client = self._client_with_fake_session(_FakeCallToolResult(text=envelope))
        try:
            result = _run(client.get_asset_info("app-payment-01"))
        finally:
            _run(client.aclose())
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["asset_id"], "app-payment-01")
        self.assertEqual(result["message"], "asset resolved")

    def test_real_mode_parses_structured_content(self) -> None:
        structured = {"success": True, "data": [1, 2, 3], "message": "ok"}
        client = self._client_with_fake_session(
            _FakeCallToolResult(structured=structured)
        )
        try:
            result = _run(client.get_critical_assets())
        finally:
            _run(client.aclose())
        self.assertTrue(result["success"])
        self.assertEqual(result["data"], [1, 2, 3])

    def test_real_mode_handles_error_result(self) -> None:
        client = self._client_with_fake_session(
            _FakeCallToolResult(text="boom", is_error=True)
        )
        try:
            result = _run(client.get_asset_info("x"))
        finally:
            _run(client.aclose())
        self.assertFalse(result["success"])
        self.assertIn("boom", result["message"])

    def test_real_mode_handles_non_json_text(self) -> None:
        client = self._client_with_fake_session(
            _FakeCallToolResult(text="not-json-content")
        )
        try:
            result = _run(client.get_asset_info("x"))
        finally:
            _run(client.aclose())
        self.assertFalse(result["success"])
        self.assertIn("non-json", result["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
