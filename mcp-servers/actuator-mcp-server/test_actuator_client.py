"""actuator_client.py 的本地单元测试。

测试范围：

- ``execute_strategy`` 的 4 项安全检查（拒绝 / warning 路径）
- ``execute_strategy`` 真实 HTTP（用 fake httpx client 注入）
- 真实 HTTP 失败时降级到 mock_fallback 的行为
- ``rollback_strategy`` / ``get_execution_status`` / ``list_executions`` 的 mock 模式
- ``list_executions`` 的本地 limit 裁剪
- 输入参数的合法性校验

不依赖 mcp 包，直接 ``import actuator_client``。

运行::

    cd autonomous-defense-system/mcp-servers/actuator-mcp-server
    python -m unittest test_actuator_client.py -v
"""
from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import MagicMock

import actuator_client as ac


# ---------------------------------------------------------------------------
# 测试夹具
# ---------------------------------------------------------------------------


def _legal_strategy() -> dict[str, Any]:
    """完全合法的策略：通过校验 + 含 rollback + 含 ttl + 状态 approved。"""
    return {
        "strategyId": "stg-actuator-legal",
        "threatType": "PHISHING",
        "targetLayer": "APPLICATION",
        "actions": [
            {
                "type": "APPLY_WAF_RULE",
                "target": "/api/login",
                "parameters": {"action": "block"},
            }
        ],
        "scope": {"assets": ["dmz-api-01"]},
        "ttl": 1800,
        "rollbackPlan": {
            "planId": "rb-1",
            "steps": ["disable_rule"],
            "triggerCondition": "manual",
        },
        "status": "approved_for_execution",
        "human_approval_required": False,
    }


def _high_risk_strategy() -> dict[str, Any]:
    """高风险动作策略，用来测试 rollback / ttl 缺失的拒绝路径。"""
    return {
        "strategyId": "stg-actuator-high-risk",
        "threatType": "MALWARE",
        "targetLayer": "ENDPOINT",
        "actions": [
            {"type": "ISOLATE_HOST", "target": "host-01"},
            {"type": "BLOCK_IP", "target": "10.10.1.1"},
        ],
        "scope": {"assets": ["host-01"]},
        "status": "approved_for_execution",
        "human_approval_required": False,
        "ttl": 600,
        "rollbackPlan": {"planId": "rb-2", "steps": ["unblock"], "triggerCondition": "auto"},
    }


def _api_response(data: Any) -> dict[str, Any]:
    """模拟 actuator-service 的 ApiResponse 信封。"""
    return {"success": True, "code": "OK", "message": "ok", "data": data, "timestamp": "x"}


def _make_fake_response(json_payload: Any, status_code: int = 200):
    """构造一个最小可用的 fake httpx Response。"""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_payload

    def _raise_for_status() -> None:
        if status_code >= 400:
            raise __import__("httpx").HTTPStatusError(
                "boom", request=MagicMock(), response=resp
            )

    resp.raise_for_status.side_effect = _raise_for_status
    return resp


# ---------------------------------------------------------------------------
# 安全检查：拒绝路径
# ---------------------------------------------------------------------------


class PreExecuteCheckTests(unittest.TestCase):
    """execute_strategy 的 4 项安全检查必须按需求拒绝/告警。"""

    def setUp(self) -> None:
        self.client = ac.ActuatorClient(mode=ac.MODE_REAL)

    # 人工审批边界守门：使用固定文案，data 中带 auto_execution_allowed=False
    _APPROVAL_MSG = (
        "Strategy requires human approval and cannot be executed automatically."
    )

    def test_human_approval_required_blocks_execution(self) -> None:
        strategy = _legal_strategy()
        strategy["human_approval_required"] = True
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        # 必须使用 spec 规定的固定 message
        self.assertEqual(result["message"], self._APPROVAL_MSG)
        self.assertEqual(result["data"]["execution_record"], None)
        self.assertEqual(result["data"]["human_approval_required"], True)
        self.assertEqual(result["data"]["auto_execution_allowed"], False)
        self.assertEqual(result["data"]["block_reason"], "human_approval_required=true")

    def test_human_approval_in_metadata_also_blocks(self) -> None:
        # 兼容旧约定：metadata.human_approval=true 也应该被识别
        strategy = _legal_strategy()
        strategy.pop("human_approval_required", None)
        strategy["metadata"] = {"human_approval": True}
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], self._APPROVAL_MSG)

    def test_auto_execution_allowed_false_blocks_execution(self) -> None:
        """Phase 5: auto_execution_allowed=False 必须直接拒绝（最高优先级）。"""
        strategy = _legal_strategy()
        strategy["auto_execution_allowed"] = False
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], self._APPROVAL_MSG)
        self.assertEqual(result["data"]["block_reason"], "auto_execution_allowed=false")
        self.assertEqual(result["data"]["auto_execution_allowed"], False)

    def test_auto_execution_allowed_false_short_circuits_other_checks(self) -> None:
        """即便 status=approved_for_execution 且其他都齐全，禁止位仍优先拒绝。"""
        strategy = _legal_strategy()
        strategy["status"] = "approved_for_execution"  # 满足后续 pre-check
        strategy["auto_execution_allowed"] = False
        # 同时给一个 rollback_plan + ttl 都齐全的 strategy
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], self._APPROVAL_MSG)

    def test_approval_reason_and_safety_checks_propagated(self) -> None:
        """approval_reason 和 safety_checks 必须透传到 data 里。"""
        strategy = _legal_strategy()
        strategy["auto_execution_allowed"] = False
        strategy["approval_reason"] = ["Critical assets impact: severity=CRITICAL"]
        strategy["safety_checks"] = [
            {
                "id": "critical_assets_impacted",
                "label": "Critical assets impact",
                "passed": False,
                "detail": "event severity=CRITICAL",
            }
        ]
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertEqual(result["data"]["approval_reason"], strategy["approval_reason"])
        self.assertEqual(result["data"]["safety_checks"], strategy["safety_checks"])

    def test_auto_execution_allowed_true_still_subject_to_other_checks(self) -> None:
        """auto_execution_allowed=True 不能跳过 status / rollback / ttl 等其它检查。"""
        strategy = _legal_strategy()
        strategy["auto_execution_allowed"] = True
        strategy["status"] = "needs_revision"  # 后续 pre-check 应当拒绝
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        # 应该走的是 pre-check 失败路径，而不是人工审批路径
        self.assertNotEqual(result["message"], self._APPROVAL_MSG)
        self.assertIn("status", result["message"].lower())

    def test_status_not_approved_blocks_execution(self) -> None:
        strategy = _legal_strategy()
        strategy["status"] = "needs_revision"
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertIn("not 'approved_for_execution'", result["message"])

    def test_status_missing_emits_warning_only(self) -> None:
        # 没有 status 字段 -> warning，不拒绝；执行流程进入 mock_fallback
        # （因为 real 模式没有 actuator-service 在线）
        strategy = _legal_strategy()
        strategy.pop("status", None)
        # 把模式改成 mock，让我们关注 warning 字段而非 HTTP
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        result = client.execute_strategy(strategy)
        self.assertTrue(result["success"])
        warnings = result["data"]["warnings"]
        self.assertTrue(any("status is missing" in w for w in warnings))

    def test_high_risk_without_rollback_blocks(self) -> None:
        strategy = _high_risk_strategy()
        strategy.pop("rollbackPlan", None)
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertIn("rollback_plan is missing", result["message"])

    def test_high_risk_without_ttl_blocks(self) -> None:
        strategy = _high_risk_strategy()
        strategy.pop("ttl", None)
        result = self.client.execute_strategy(strategy)
        self.assertFalse(result["success"])
        self.assertIn("ttl is missing", result["message"])

    def test_low_risk_without_ttl_only_warns(self) -> None:
        # 只有非高风险动作时 ttl 缺失只给 warning，不拒绝
        strategy = _legal_strategy()  # APPLY_WAF_RULE 非高风险
        strategy.pop("ttl", None)
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        result = client.execute_strategy(strategy)
        self.assertTrue(result["success"])
        warnings = result["data"]["warnings"]
        self.assertTrue(any("ttl is missing" in w for w in warnings))

    def test_ttl_minutes_field_is_recognized(self) -> None:
        # 用 ttl_minutes 替代 ttl，应被认作有 TTL
        strategy = _high_risk_strategy()
        strategy.pop("ttl", None)
        strategy["ttl_minutes"] = 30
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        result = client.execute_strategy(strategy)
        self.assertTrue(result["success"])
        # 没有 ttl missing 的 warning
        self.assertFalse(
            any("ttl is missing" in w for w in result["data"]["warnings"])
        )


# ---------------------------------------------------------------------------
# 真实 HTTP 路径：用 fake client 注入
# ---------------------------------------------------------------------------


class RealHttpPathTests(unittest.TestCase):
    """用注入的 fake httpx client 验证 URL/请求体/解包行为。"""

    def test_execute_strategy_posts_to_correct_endpoint(self) -> None:
        fake_record = {
            "executionId": "exec-real-001",
            "strategyId": "stg-actuator-legal",
            "status": "SUCCEEDED",
            "ttl": 1800,
        }
        fake_http = MagicMock()
        fake_http.post.return_value = _make_fake_response(_api_response(fake_record))

        client = ac.ActuatorClient(
            base_url="http://example.test:8081",
            mode=ac.MODE_REAL,
            http_client=fake_http,
        )
        result = client.execute_strategy(_legal_strategy())
        self.assertTrue(result["success"])

        # 1) 调用了 POST /api/strategies/execute
        fake_http.post.assert_called_once()
        called_url = fake_http.post.call_args.args[0]
        self.assertEqual(called_url, "http://example.test:8081/api/strategies/execute")

        # 2) 请求体只包含 actuator-service 期望的字段
        called_body = fake_http.post.call_args.kwargs["json"]
        self.assertEqual(
            set(called_body.keys()),
            {"strategyId", "threatType", "targetLayer", "actions", "scope", "ttl", "rollbackPlan"},
        )
        self.assertNotIn("status", called_body)
        self.assertNotIn("human_approval_required", called_body)

        # 3) ApiResponse.data 被解包出来
        self.assertEqual(result["data"]["execution_record"], fake_record)
        self.assertEqual(result["data"]["mode"], "real")

    def test_real_call_failure_falls_back_to_mock(self) -> None:
        fake_http = MagicMock()
        # 让 post 直接抛 httpx 错误
        import httpx as _httpx

        fake_http.post.side_effect = _httpx.ConnectError("connection refused")

        client = ac.ActuatorClient(
            base_url="http://example.test:8081",
            mode=ac.MODE_REAL,
            http_client=fake_http,
        )
        result = client.execute_strategy(_legal_strategy())
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["mode"], "mock_fallback")
        # warnings 中包含 actuator-service unreachable
        self.assertTrue(
            any("unreachable" in w for w in result["data"]["warnings"])
        )

    def test_rollback_strategy_real_call(self) -> None:
        fake_record = {
            "executionId": "exec-real-002",
            "strategyId": "stg-x",
            "status": "SUCCEEDED",
            "rollbackStatus": "SUCCEEDED",
        }
        fake_http = MagicMock()
        fake_http.post.return_value = _make_fake_response(_api_response(fake_record))

        client = ac.ActuatorClient(mode=ac.MODE_REAL, http_client=fake_http)
        result = client.rollback_strategy("stg-x")
        self.assertTrue(result["success"])
        url = fake_http.post.call_args.args[0]
        self.assertTrue(url.endswith("/api/strategies/stg-x/rollback"))
        self.assertEqual(result["data"]["execution_record"], fake_record)

    def test_get_execution_status_real_call(self) -> None:
        fake_record = {"executionId": "e-1", "strategyId": "s-1", "status": "RUNNING"}
        fake_http = MagicMock()
        fake_http.get.return_value = _make_fake_response(_api_response(fake_record))

        client = ac.ActuatorClient(mode=ac.MODE_REAL, http_client=fake_http)
        result = client.get_execution_status("e-1")
        self.assertTrue(result["success"])
        url = fake_http.get.call_args.args[0]
        self.assertTrue(url.endswith("/api/executions/e-1"))
        self.assertEqual(result["data"]["execution_record"], fake_record)

    def test_list_executions_real_call_with_limit(self) -> None:
        records = [
            {"executionId": f"e-{i}", "strategyId": f"s-{i}", "status": "SUCCEEDED"}
            for i in range(5)
        ]
        fake_http = MagicMock()
        fake_http.get.return_value = _make_fake_response(_api_response(records))

        client = ac.ActuatorClient(mode=ac.MODE_REAL, http_client=fake_http)
        result = client.list_executions(limit=3)
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["count"], 3)
        self.assertEqual(len(result["data"]["executions"]), 3)
        self.assertEqual(result["data"]["limit"], 3)


# ---------------------------------------------------------------------------
# Mock 模式
# ---------------------------------------------------------------------------


class MockModeTests(unittest.TestCase):
    """ACTUATOR_MODE=mock 时不应发起任何 HTTP 调用。"""

    def setUp(self) -> None:
        self.client = ac.ActuatorClient(mode=ac.MODE_MOCK)

    def test_mock_execute_returns_synthetic_record(self) -> None:
        result = self.client.execute_strategy(_legal_strategy())
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["mode"], ac.MODE_MOCK)
        record = result["data"]["execution_record"]
        self.assertTrue(record["executionId"].startswith("exec-mock-"))
        self.assertEqual(record["status"], "SUCCEEDED")
        self.assertEqual(record["strategyId"], "stg-actuator-legal")

    def test_mock_rollback_returns_synthetic_record(self) -> None:
        result = self.client.rollback_strategy("stg-x")
        self.assertTrue(result["success"])
        record = result["data"]["execution_record"]
        self.assertEqual(record["strategyId"], "stg-x")
        self.assertEqual(record["rollbackStatus"], "SUCCEEDED")

    def test_mock_list_caps_at_3_records(self) -> None:
        # mock 模式最多返回 3 条样本
        result = self.client.list_executions(limit=10)
        self.assertTrue(result["success"])
        self.assertLessEqual(result["data"]["count"], 3)

    def test_mock_list_respects_smaller_limit(self) -> None:
        result = self.client.list_executions(limit=1)
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["count"], 1)


# ---------------------------------------------------------------------------
# 输入参数校验
# ---------------------------------------------------------------------------


class InputValidationTests(unittest.TestCase):
    def test_non_dict_strategy_returns_failure(self) -> None:
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        result = client.execute_strategy("not-a-dict")  # type: ignore[arg-type]
        self.assertFalse(result["success"])
        self.assertIn("must be a dict", result["message"])

    def test_empty_strategy_id_for_rollback(self) -> None:
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        result = client.rollback_strategy("   ")
        self.assertFalse(result["success"])
        self.assertIn("non-empty", result["message"])

    def test_invalid_limit_for_list(self) -> None:
        client = ac.ActuatorClient(mode=ac.MODE_MOCK)
        self.assertFalse(client.list_executions(0)["success"])
        self.assertFalse(client.list_executions(-1)["success"])
        self.assertFalse(client.list_executions("x")["success"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 模式与默认值
# ---------------------------------------------------------------------------


class ConfigTests(unittest.TestCase):
    def test_default_base_url_is_8081(self) -> None:
        # 与 actuator-service/application.yml 中 server.port=8081 对齐
        client = ac.ActuatorClient()
        self.assertEqual(client.base_url, "http://localhost:8081")

    def test_unknown_mode_falls_back_to_real(self) -> None:
        client = ac.ActuatorClient(mode="weird")
        self.assertEqual(client.mode, ac.MODE_REAL)

    def test_explicit_base_url_strips_trailing_slash(self) -> None:
        client = ac.ActuatorClient(base_url="http://example.test:9999/")
        self.assertEqual(client.base_url, "http://example.test:9999")


# ---------------------------------------------------------------------------
# 工具方法的边界
# ---------------------------------------------------------------------------


class HelperFunctionTests(unittest.TestCase):
    def test_resolve_ttl_seconds_prefers_seconds_field(self) -> None:
        # ttl 优先于 ttl_minutes
        self.assertEqual(ac._resolve_ttl_seconds({"ttl": 60, "ttl_minutes": 5}), 60)

    def test_resolve_ttl_seconds_uses_minutes_when_seconds_absent(self) -> None:
        self.assertEqual(ac._resolve_ttl_seconds({"ttl_minutes": 5}), 300)

    def test_resolve_rollback_plan_requires_content(self) -> None:
        # 空字典或没有 planId/steps 的 dict 都视为无效
        self.assertIsNone(ac._resolve_rollback_plan({"rollbackPlan": {}}))
        self.assertIsNone(
            ac._resolve_rollback_plan({"rollbackPlan": {"triggerCondition": "x"}})
        )
        self.assertIsNotNone(
            ac._resolve_rollback_plan({"rollbackPlan": {"planId": "p1"}})
        )

    def test_high_risk_action_detection(self) -> None:
        self.assertTrue(
            ac._has_high_risk_action({"actions": [{"type": "BLOCK_IP", "target": "1.2.3.4"}]})
        )
        self.assertFalse(
            ac._has_high_risk_action({"actions": [{"type": "ALERT_ONLY", "target": "x"}]})
        )

    def test_unwrap_api_response_handles_envelope_and_raw(self) -> None:
        self.assertEqual(
            ac._unwrap_api_response({"success": True, "data": {"x": 1}}), {"x": 1}
        )
        # 非约定形态原样返回
        self.assertEqual(ac._unwrap_api_response([1, 2, 3]), [1, 2, 3])

    def test_build_strategy_request_drops_extra_fields(self) -> None:
        body = ac._build_strategy_request(
            {
                "strategyId": "x",
                "threatType": "MALWARE",
                "targetLayer": "ENDPOINT",
                "actions": [],
                "scope": None,
                "ttl": 60,
                "status": "approved_for_execution",  # 不应进入请求体
                "human_approval_required": False,    # 不应进入请求体
            }
        )
        self.assertEqual(body["strategyId"], "x")
        self.assertEqual(body["scope"], {})
        self.assertNotIn("status", body)
        self.assertNotIn("human_approval_required", body)


# ---------------------------------------------------------------------------
# 服务的整体形态（json 序列化、信封一致性）
# ---------------------------------------------------------------------------


class EnvelopeContractTests(unittest.TestCase):
    """所有公共方法返回 ``{success, data, message}`` 三键，必须 JSON 可序列化。"""

    def setUp(self) -> None:
        self.client = ac.ActuatorClient(mode=ac.MODE_MOCK)

    def _assert_envelope(self, result: Any) -> None:
        self.assertIsInstance(result, dict)
        self.assertIn("success", result)
        self.assertIn("data", result)
        self.assertIn("message", result)
        # 必须 JSON 可序列化
        json.dumps(result)

    def test_execute_envelope(self) -> None:
        self._assert_envelope(self.client.execute_strategy(_legal_strategy()))

    def test_rollback_envelope(self) -> None:
        self._assert_envelope(self.client.rollback_strategy("stg-x"))

    def test_status_envelope(self) -> None:
        self._assert_envelope(self.client.get_execution_status("e-1"))

    def test_list_envelope(self) -> None:
        self._assert_envelope(self.client.list_executions(5))


if __name__ == "__main__":
    unittest.main(verbosity=2)
