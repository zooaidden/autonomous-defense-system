"""policy_service 的本地单元测试。

直接在本目录运行：

    python -m unittest test_policy_service.py    # 标准库
    python test_policy_service.py                 # 等价
    pytest -q                                     # 也可以用 pytest

这些用例不依赖 mcp 包，直接 import policy_service 进行黑盒验证。
覆盖场景：
    * 合法策略全通过
    * 高风险策略命中 critical 数据库 + 缺 human_approval（多条 violation）
    * 缺少 TTL 的生产路径阻断策略
    * 缺少 rollback_plan 的高风险策略
    * WAF 过宽规则
    * Firewall 缺 5 元组
    * K8s replicas 低于阈值
    * suggest_safer_strategy 返回的 patch 数量与 violation 一致
    * require_human_approval 不会因已声明 human_approval 而错误升级
    * 自定义规则集注入路径
"""
from __future__ import annotations

import copy
import unittest
from pathlib import Path

import policy_service as ps


# ---------------------------------------------------------------------------
# 公用 fixture
# ---------------------------------------------------------------------------


def _legal_strategy() -> dict[str, object]:
    """构造一个完全合规的策略，便于多条用例复用。"""
    return {
        "strategyId": "stg-legal-001",
        "actions": [
            {
                "type": "APPLY_WAF_RULE",
                "target": "/api/login",
                "parameters": {
                    "action": "block",
                    "path": "/api/login",
                    "rule_id": "rule-100",
                },
            },
            {
                "type": "APPLY_FIREWALL_RULE",
                "target": "fw-perimeter-01",
                "parameters": {
                    "action": "deny",
                    "source": "203.0.113.0/24",
                    "destination": "10.10.1.20",
                    "port": 443,
                    "protocol": "tcp",
                },
            },
        ],
        "scope": {"assets": ["dmz-api-01"]},
        "ttl": 1800,
        "rollbackPlan": {
            "planId": "rb-001",
            "steps": ["remove_temporary_rules", "restore_network_policy"],
            "triggerCondition": "false_positive_confirmed",
        },
    }


def _high_risk_critical_db_strategy() -> dict[str, object]:
    """对 critical 数据库做全量阻断、且未声明 human_approval。"""
    return {
        "strategyId": "stg-high-risk-001",
        "actions": [
            {
                "type": "BLOCK_IP",
                "target": "10.30.1.10",
                "parameters": {},
            },
            {
                "type": "ISOLATE_HOST",
                "target": "db-primary-01",
                "parameters": {},
            },
        ],
        "scope": {"assets": ["db-primary-01"]},
        "ttl": 1800,
        "rollbackPlan": {
            "planId": "rb-002",
            "steps": ["restore_network_policy"],
            "triggerCondition": "manual_review",
        },
    }


def _missing_ttl_strategy() -> dict[str, object]:
    """生产路径阻断但缺少 TTL。"""
    return {
        "strategyId": "stg-no-ttl-001",
        "actions": [
            {
                "type": "BLOCK_IP",
                "target": "10.20.1.10",
                "parameters": {},
            }
        ],
        "scope": {"assets": ["app-payment-01"]},
        "rollbackPlan": {
            "planId": "rb-003",
            "steps": ["remove_block"],
            "triggerCondition": "false_positive",
        },
        "metadata": {"human_approval": True},
    }


def _missing_rollback_strategy() -> dict[str, object]:
    """高风险动作但缺 rollback_plan。"""
    return {
        "strategyId": "stg-no-rollback-001",
        "actions": [
            {
                "type": "BLOCK_IP",
                "target": "203.0.113.42",
                "parameters": {},
            }
        ],
        "scope": {"assets": []},
        "ttl": 1800,
    }


# ---------------------------------------------------------------------------
# validate_strategy
# ---------------------------------------------------------------------------


class ValidateStrategyTests(unittest.TestCase):
    """覆盖 7 条规则在 validate_strategy 上的端到端表现。"""

    def test_legal_strategy_is_valid(self) -> None:
        result = ps.validate_strategy(_legal_strategy())
        self.assertTrue(result["valid"], msg=result["violations"])
        self.assertEqual(result["violations"], [])
        # 合法策略本身不命中关键资产 → 不需要人工审批
        self.assertFalse(result["requires_human_approval"])
        # suggestions 与 violation 数一致（合法时也应为空）
        self.assertEqual(len(result["suggestions"]), 0)

    def test_high_risk_strategy_yields_multiple_violations(self) -> None:
        result = ps.validate_strategy(_high_risk_critical_db_strategy())
        self.assertFalse(result["valid"])
        rule_ids = {v["rule_id"] for v in result["violations"]}
        # 至少应包含：001（critical DB 全量阻断）+ 007（缺 human_approval）
        self.assertIn("RULE-001", rule_ids)
        self.assertIn("RULE-007", rule_ids)
        self.assertTrue(result["requires_human_approval"])
        # 每条 violation 都应当生成对应的 suggestion
        self.assertGreaterEqual(len(result["suggestions"]), len(result["violations"]))

    def test_missing_ttl_triggers_rule_002(self) -> None:
        result = ps.validate_strategy(_missing_ttl_strategy())
        self.assertFalse(result["valid"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("RULE-002", rule_ids)
        # 至少有一条 suggestion 是给 RULE-002 的（patch field=ttl）
        ttl_suggestions = [s for s in result["suggestions"] if s["rule_id"] == "RULE-002"]
        self.assertTrue(ttl_suggestions)
        self.assertEqual(ttl_suggestions[0]["patch"]["field"], "ttl")

    def test_missing_rollback_triggers_rule_003(self) -> None:
        result = ps.validate_strategy(_missing_rollback_strategy())
        self.assertFalse(result["valid"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("RULE-003", rule_ids)
        rb_suggestions = [s for s in result["suggestions"] if s["rule_id"] == "RULE-003"]
        self.assertTrue(rb_suggestions)
        self.assertEqual(rb_suggestions[0]["patch"]["field"], "rollbackPlan")

    def test_waf_block_without_matcher_triggers_rule_005(self) -> None:
        strategy = {
            "strategyId": "stg-waf-broad",
            "actions": [
                {
                    "type": "APPLY_WAF_RULE",
                    "target": "/api/*",
                    "parameters": {"action": "block"},
                }
            ],
            "scope": {"assets": []},
            "ttl": 1800,
            "rollbackPlan": {
                "planId": "rb",
                "steps": ["x"],
                "triggerCondition": "y",
            },
        }
        result = ps.validate_strategy(strategy)
        # RULE-005 是 medium → 进 warnings
        warning_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("RULE-005", warning_ids)
        # RULE-005 是 medium，valid 不被它降为 False
        self.assertTrue(result["valid"])

    def test_firewall_missing_5tuple_triggers_rule_006(self) -> None:
        strategy = {
            "strategyId": "stg-fw-broad",
            "actions": [
                {
                    "type": "APPLY_FIREWALL_RULE",
                    "target": "fw-perimeter",
                    "parameters": {"action": "deny", "source": "0.0.0.0/0"},
                }
            ],
            "scope": {"assets": []},
            "ttl": 1800,
            "rollbackPlan": {
                "planId": "rb",
                "steps": ["x"],
                "triggerCondition": "y",
            },
        }
        result = ps.validate_strategy(strategy)
        warning_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("RULE-006", warning_ids)
        # 应该明确给出缺哪些字段
        msg = next(w["message"] for w in result["warnings"] if w["rule_id"] == "RULE-006")
        for k in ("destination", "port", "protocol"):
            self.assertIn(k, msg)

    def test_k8s_below_min_replicas_triggers_rule_004(self) -> None:
        strategy = {
            "strategyId": "stg-k8s-too-small",
            "actions": [
                {
                    "type": "SCALE_PROTECTION",
                    "target": "deployment/payment",
                    "parameters": {"replicas": 1},
                }
            ],
            "scope": {"assets": []},
        }
        result = ps.validate_strategy(strategy)
        warning_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("RULE-004", warning_ids)

    def test_critical_db_block_with_ingress_only_passes(self) -> None:
        """ingress_only 收敛参数应当让 RULE-001 放行。"""
        strategy = copy.deepcopy(_high_risk_critical_db_strategy())
        for act in strategy["actions"]:
            act["parameters"] = {"scope": "ingress_only"}
        # 配合声明 human_approval=true 让 RULE-007 也放行
        strategy["metadata"] = {"human_approval": True}
        result = ps.validate_strategy(strategy)
        rule_ids = {v["rule_id"] for v in result["violations"]}
        self.assertNotIn("RULE-001", rule_ids)
        self.assertNotIn("RULE-007", rule_ids)


# ---------------------------------------------------------------------------
# check_business_constraints
# ---------------------------------------------------------------------------


class CheckBusinessConstraintsTests(unittest.TestCase):
    """check_business_constraints 只跑业务影响相关的子集规则。"""

    def test_business_block_on_db_violates(self) -> None:
        result = ps.check_business_constraints(_high_risk_critical_db_strategy())
        self.assertFalse(result["valid"])
        rule_ids = {v["rule_id"] for v in result["violations"]}
        self.assertIn("RULE-001", rule_ids)
        # check_business_constraints 不直接产出 RULE-007（那是审批规则）
        self.assertNotIn("RULE-007", rule_ids)
        self.assertTrue(result["requires_human_approval"])

    def test_business_check_passes_for_legal_strategy(self) -> None:
        result = ps.check_business_constraints(_legal_strategy())
        self.assertTrue(result["valid"])
        self.assertFalse(result["requires_human_approval"])

    def test_business_check_does_not_complain_about_rollback(self) -> None:
        """RULE-003 不应在业务约束维度下出现。"""
        strategy = _missing_rollback_strategy()
        result = ps.check_business_constraints(strategy)
        rule_ids = {v["rule_id"] for v in result["violations"]}
        self.assertNotIn("RULE-003", rule_ids)


# ---------------------------------------------------------------------------
# require_human_approval
# ---------------------------------------------------------------------------


class RequireHumanApprovalTests(unittest.TestCase):
    """require_human_approval 的若干判定路径。"""

    def test_legal_strategy_does_not_require(self) -> None:
        result = ps.require_human_approval(_legal_strategy())
        self.assertFalse(result["requires_human_approval"])

    def test_critical_asset_block_requires_approval(self) -> None:
        result = ps.require_human_approval(_high_risk_critical_db_strategy())
        self.assertTrue(result["requires_human_approval"])

    def test_already_declared_human_approval_short_circuits(self) -> None:
        """已经在 metadata 里声明 human_approval=true 且未触发 RULE-001 时不再升级。"""
        strategy = copy.deepcopy(_high_risk_critical_db_strategy())
        # 把 BLOCK 动作改成纯收敛动作以避开 RULE-001
        for act in strategy["actions"]:
            act["type"] = "RESTRICT_EGRESS"
            act["parameters"] = {"scope": "ingress_only"}
        strategy["metadata"] = {"human_approval": True}
        result = ps.require_human_approval(strategy)
        self.assertFalse(result["requires_human_approval"])

    def test_high_criticality_asset_warns(self) -> None:
        """命中 high（非 critical）级别资产时应给出 warning + 建议人工。"""
        strategy = {
            "strategyId": "stg-high-asset",
            "actions": [
                {
                    "type": "BLOCK_IP",
                    "target": "dmz-api-01",
                    "parameters": {},
                }
            ],
            "scope": {"assets": ["dmz-api-01"]},
            "ttl": 1800,
            "rollbackPlan": {
                "planId": "rb",
                "steps": ["x"],
                "triggerCondition": "y",
            },
        }
        result = ps.require_human_approval(strategy)
        self.assertTrue(result["requires_human_approval"])
        # warnings 中能看到 high 级提示
        self.assertTrue(result["warnings"])


# ---------------------------------------------------------------------------
# suggest_safer_strategy
# ---------------------------------------------------------------------------


class SuggestSaferStrategyTests(unittest.TestCase):
    """suggest_safer_strategy 应针对 violation 给出可执行 patch。"""

    def test_suggestions_match_violations_count(self) -> None:
        result = ps.suggest_safer_strategy(_high_risk_critical_db_strategy())
        # 至少应给出一条 RULE-001 的 patch
        rule001 = [s for s in result["suggestions"] if s["rule_id"] == "RULE-001"]
        self.assertTrue(rule001)
        self.assertIn("scope", str(rule001[0]["patch"]))

    def test_suggestion_for_missing_ttl(self) -> None:
        result = ps.suggest_safer_strategy(_missing_ttl_strategy())
        ttl_suggestions = [s for s in result["suggestions"] if s["rule_id"] == "RULE-002"]
        self.assertTrue(ttl_suggestions)
        self.assertEqual(ttl_suggestions[0]["patch"]["field"], "ttl")
        self.assertGreaterEqual(int(ttl_suggestions[0]["patch"]["value"]), 60)

    def test_suggestion_for_missing_rollback(self) -> None:
        result = ps.suggest_safer_strategy(_missing_rollback_strategy())
        rb_suggestions = [s for s in result["suggestions"] if s["rule_id"] == "RULE-003"]
        self.assertTrue(rb_suggestions)
        patch = rb_suggestions[0]["patch"]
        self.assertEqual(patch["field"], "rollbackPlan")
        self.assertIn("steps", patch["value"])
        self.assertIn("triggerCondition", patch["value"])


# ---------------------------------------------------------------------------
# 输入容错 / 自定义规则集
# ---------------------------------------------------------------------------


class InputAndCustomRulesTests(unittest.TestCase):
    """边界输入与自定义规则集的注入。"""

    def test_non_dict_input_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            ps.validate_strategy("not-a-dict")  # type: ignore[arg-type]

    def test_empty_actions_is_valid(self) -> None:
        result = ps.validate_strategy({"strategyId": "stg-empty", "actions": []})
        self.assertTrue(result["valid"])
        self.assertEqual(result["violations"], [])

    def test_custom_rules_can_override_default(self) -> None:
        """允许通过参数注入自定义规则集，验证函数纯净度。"""
        custom_rules = {
            "rules": [
                {
                    "id": "RULE-003",
                    "name": "high_risk_action_requires_rollback",
                    "severity": "high",
                    "description": "test",
                    "applies_to_actions": ["BLOCK_IP"],
                    "remediation": "add rollback",
                }
            ],
            "high_risk_actions": ["BLOCK_IP"],
            "critical_assets": [],
            "production_paths": [],
            "limits": {"k8s_min_replicas": 2, "ttl_min_seconds": 60, "ttl_max_seconds": 86400},
        }
        result = ps.validate_strategy(_missing_rollback_strategy(), custom_rules)
        self.assertFalse(result["valid"])
        self.assertEqual(
            [v["rule_id"] for v in result["violations"]], ["RULE-003"]
        )

    def test_default_rules_load(self) -> None:
        rules = ps.load_rules()
        self.assertIn("rules", rules)
        rule_ids = {r["id"] for r in rules["rules"]}
        self.assertEqual(
            rule_ids,
            {f"RULE-00{i}" for i in range(1, 8)},
        )

    def test_default_rules_path_exists(self) -> None:
        self.assertTrue(Path(ps.DEFAULT_RULES_PATH).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
