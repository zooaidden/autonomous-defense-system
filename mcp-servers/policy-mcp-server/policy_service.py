"""policy-mcp-server 的纯 Python 业务层。

本模块刻意不引入任何 MCP / FastMCP 依赖，``server.py`` 只是把这里的公共
函数包装为 MCP tool；``test_policy_service.py`` 直接 import 本模块进行
单元测试，无需安装 ``mcp`` 包。

公共函数（与 MCP tool 一一对应）：
    * load_rules(path=None) / get_rules() / reload_default_rules()
    * validate_strategy(strategy, rules=None)
    * check_business_constraints(strategy, rules=None)
    * require_human_approval(strategy, rules=None)
    * suggest_safer_strategy(strategy, rules=None)

所有公共函数都返回符合 spec 的统一结构：
    {
        "valid": bool,
        "violations": list[dict],
        "warnings": list[dict],
        "requires_human_approval": bool,
        "suggestions": list[dict],
    }

violations / warnings 中的每条记录结构：
    {
        "rule_id": "RULE-001",
        "rule_name": "no_full_block_on_critical_database",
        "severity": "critical",
        "action_index": 0,                  # 命中此规则的 action 在 actions[] 中的索引（无关 action 时为 None）
        "action_type": "BLOCK_IP",
        "target": "10.30.1.10",
        "message": "...",
        "remediation": "...",
    }

suggestions 的结构：
    {
        "rule_id": "RULE-001",
        "title": "..",
        "detail": "..",
        "patch": { "field": "...", "operation": "set|append", "value": ... },
    }

模块对策略字段做了驼峰 / 蛇形双写兼容：
    * ``ttl`` 与 ``ttl_minutes``（后者按 60 倍换算）
    * ``rollbackPlan`` / ``rollback_plan``
    * ``requires_human_approval`` / ``metadata.human_approval`` / ``humanApproval``
便于上游 agent-brain（驼峰）与外部脚手架（蛇形）共用。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# 公共常量
# ---------------------------------------------------------------------------

# 默认规则文件位置（与 server.py 同目录）
DEFAULT_RULES_PATH: Path = Path(__file__).parent / "policy_rules.json"


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class PolicyServiceError(Exception):
    """策略服务的基础异常。"""


class RulesNotLoadedError(PolicyServiceError):
    """规则文件无法解析或缺少必要字段时抛出。"""


# ---------------------------------------------------------------------------
# 规则加载（懒加载 + 可重置）
# ---------------------------------------------------------------------------


_DEFAULT_RULES_CACHE: Optional[dict[str, Any]] = None


def load_rules(path: Optional[Path | str] = None) -> dict[str, Any]:
    """从磁盘加载并校验一份 policy_rules.json。

    参数 ``path`` 缺省时使用 ``DEFAULT_RULES_PATH``。本函数不缓存任何
    结果，``get_rules()`` 才负责进程级缓存。
    """
    p = Path(path) if path else DEFAULT_RULES_PATH
    if not p.exists():
        raise RulesNotLoadedError(f"policy rules file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RulesNotLoadedError(f"invalid JSON in {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise RulesNotLoadedError("rules root must be an object")
    if "rules" not in data or not isinstance(data["rules"], list):
        raise RulesNotLoadedError("rules.rules[] is required")
    # 给所有可选集合补上空默认值，避免下游每次都判存
    data.setdefault("critical_assets", [])
    data.setdefault("production_paths", [])
    data.setdefault("high_risk_actions", [])
    data.setdefault("limits", {})
    return data


def get_rules(rules: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """获取生效的规则集（默认懒加载 + 进程级缓存）。

    单元测试可以传入自定义 ``rules`` 字典，避免依赖磁盘文件。
    """
    if rules is not None:
        return rules
    global _DEFAULT_RULES_CACHE
    if _DEFAULT_RULES_CACHE is None:
        _DEFAULT_RULES_CACHE = load_rules()
    return _DEFAULT_RULES_CACHE


def reload_default_rules() -> dict[str, Any]:
    """显式重载默认规则文件，便于运行期热更新。"""
    global _DEFAULT_RULES_CACHE
    _DEFAULT_RULES_CACHE = load_rules()
    return _DEFAULT_RULES_CACHE


# ---------------------------------------------------------------------------
# 输入归一化（兼容 agent-brain 驼峰与 snake_case）
# ---------------------------------------------------------------------------


def _ensure_dict(strategy: Any) -> dict[str, Any]:
    """确保入参是 dict；不是的话抛 TypeError 让上游统一封装失败信封。"""
    if not isinstance(strategy, dict):
        raise TypeError(f"strategy must be a dict, got {type(strategy).__name__}")
    return strategy


def _get_actions(strategy: dict[str, Any]) -> list[dict[str, Any]]:
    """统一拿到 actions 列表，缺失返回空 list。"""
    actions = strategy.get("actions") or []
    if not isinstance(actions, list):
        return []
    # 跳过非 dict 元素，避免后续 .get 崩
    return [a for a in actions if isinstance(a, dict)]


def _get_action_type(action: dict[str, Any]) -> str:
    return str(action.get("type") or "").upper()


def _get_action_target(action: dict[str, Any]) -> str:
    return str(action.get("target") or "")


def _get_action_params(action: dict[str, Any]) -> dict[str, Any]:
    p = action.get("parameters") or {}
    return p if isinstance(p, dict) else {}


def _get_ttl_seconds(strategy: dict[str, Any]) -> Optional[int]:
    """同时支持 ``ttl`` 与 ``ttl_minutes``（后者按 60 倍换算）。"""
    if "ttl" in strategy and strategy["ttl"] is not None:
        try:
            return int(strategy["ttl"])
        except (TypeError, ValueError):
            return None
    if "ttl_minutes" in strategy and strategy["ttl_minutes"] is not None:
        try:
            return int(strategy["ttl_minutes"]) * 60
        except (TypeError, ValueError):
            return None
    return None


def _get_rollback_plan(strategy: dict[str, Any]) -> Optional[dict[str, Any]]:
    """兼容 ``rollbackPlan`` / ``rollback_plan`` 双写。"""
    rb = strategy.get("rollbackPlan") or strategy.get("rollback_plan")
    return rb if isinstance(rb, dict) else None


def _get_human_approval_flag(strategy: dict[str, Any]) -> bool:
    """从顶层 / metadata / scope 多处尝试解析 human_approval 标记。"""
    candidates: list[Any] = [
        strategy.get("requires_human_approval"),
        strategy.get("requiresHumanApproval"),
        strategy.get("human_approval"),
        strategy.get("humanApproval"),
    ]
    md = strategy.get("metadata")
    if isinstance(md, dict):
        candidates.extend([md.get("human_approval"), md.get("humanApproval")])
    scope = strategy.get("scope")
    if isinstance(scope, dict):
        candidates.extend([scope.get("human_approval"), scope.get("humanApproval")])
    return any(bool(v) for v in candidates if v is not None)


# ---------------------------------------------------------------------------
# 关键资产 / 生产路径辅助
# ---------------------------------------------------------------------------


def _index_critical_assets(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """把 critical_assets 同时按 asset_id / ip / name 建立倒排索引。"""
    idx: dict[str, dict[str, Any]] = {}
    for a in rules.get("critical_assets", []) or []:
        if not isinstance(a, dict):
            continue
        for key in (a.get("asset_id"), a.get("ip"), a.get("name")):
            if key:
                idx[str(key)] = a
    return idx


def _is_critical_target(
    target: str, scope_assets: list[str], crit_index: dict[str, dict[str, Any]],
    *, only_database: bool = False
) -> tuple[bool, Optional[dict[str, Any]]]:
    """判断 ``target`` 或 scope.assets 中任一资产是否命中关键资产清单。

    返回 (是否命中, 命中的资产详情或 None)；``only_database=True`` 时只
    匹配 ``category=database`` 的关键资产，便于 RULE-001 这类专门规则。
    """
    candidates: list[str] = []
    if target:
        candidates.append(target)
    candidates.extend(str(a) for a in scope_assets if a)
    for key in candidates:
        info = crit_index.get(key)
        if info is None:
            continue
        if only_database and str(info.get("category", "")).lower() != "database":
            continue
        if str(info.get("criticality", "")).lower() != "critical":
            continue
        return True, info
    return False, None


def _affects_production_path(
    action: dict[str, Any], strategy: dict[str, Any], rules: dict[str, Any]
) -> bool:
    """判断 action 是否影响任何 production_path。

    判定规则（任一命中即认为影响）：
      1. action.target / scope.assets 中包含 production_path 任一端点
         所在 zone 的关键资产；
      2. action.parameters.allowlistedFlows 显式声明覆盖任一 production_path
         的命名（说明上游已意识到会影响并尝试白名单）；
      3. action.type ∈ {BLOCK_IP, ISOLATE_*, RESTRICT_EGRESS, APPLY_FIREWALL_RULE}
         且 target/scope 命中关键资产（即使非数据库也算"接近"生产路径）。
    """
    crit_index = _index_critical_assets(rules)
    target = _get_action_target(action)
    scope_assets = _scope_assets(strategy)
    params = _get_action_params(action)

    # 显式标注的 allowlistedFlows
    flows = params.get("allowlistedFlows") or params.get("allowlisted_flows") or []
    if isinstance(flows, list):
        prod_names = {str(p.get("name", "")) for p in (rules.get("production_paths") or []) if isinstance(p, dict)}
        if any(str(f) in prod_names for f in flows):
            return True

    # 命中 production_path 的端点 zone（DMZ/Internal/Database）
    prod_zones: set[str] = set()
    for p in rules.get("production_paths") or []:
        if isinstance(p, dict):
            for z in (p.get("from_zone"), p.get("to_zone")):
                if z:
                    prod_zones.add(str(z))

    for key in [target, *scope_assets]:
        info = crit_index.get(str(key))
        if info and str(info.get("zone", "")) in prod_zones:
            return True
    return False


def _scope_assets(strategy: dict[str, Any]) -> list[str]:
    scope = strategy.get("scope") or {}
    if not isinstance(scope, dict):
        return []
    raw = scope.get("assets") or []
    return [str(a) for a in raw if a]


# ---------------------------------------------------------------------------
# 各条规则的实现（每条返回 0 或多条 violation/warning）
# ---------------------------------------------------------------------------


def _make_violation(
    rule: dict[str, Any],
    *,
    action_index: Optional[int],
    action_type: str,
    target: str,
    message: str,
) -> dict[str, Any]:
    """统一构造一条 violation 记录。"""
    return {
        "rule_id": rule.get("id", ""),
        "rule_name": rule.get("name", ""),
        "severity": rule.get("severity", "medium"),
        "action_index": action_index,
        "action_type": action_type,
        "target": target,
        "message": message,
        "remediation": rule.get("remediation", ""),
    }


def _rule_by_id(rules: dict[str, Any], rule_id: str) -> dict[str, Any]:
    for r in rules.get("rules", []):
        if r.get("id") == rule_id:
            return r
    return {"id": rule_id, "name": rule_id, "severity": "medium", "remediation": ""}


def _check_rule_001_critical_db_full_block(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-001：critical 数据库不能被全量阻断。"""
    rule = _rule_by_id(rules, "RULE-001")
    out: list[dict[str, Any]] = []
    crit_idx = _index_critical_assets(rules)
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype not in (rule.get("applies_to_actions") or []):
            continue
        target = _get_action_target(act)
        hit, info = _is_critical_target(
            target, _scope_assets(strategy), crit_idx, only_database=True
        )
        if not hit:
            continue
        params = _get_action_params(act)
        # 收敛参数：ingress_only 或 allowlistedFlows 任一存在则视为已收敛
        scope = str(params.get("scope", "")).lower()
        flows = params.get("allowlistedFlows") or params.get("allowlisted_flows") or []
        if scope == "ingress_only" or (isinstance(flows, list) and flows):
            continue
        out.append(
            _make_violation(
                rule,
                action_index=i,
                action_type=atype,
                target=target,
                message=(
                    f"{atype} on critical database asset "
                    f"{info.get('asset_id') if info else target} without ingress_only/allowlistedFlows constraint"
                ),
            )
        )
    return out


def _check_rule_002_production_path_ttl(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-002：影响生产路径的阻断动作必须有合法 TTL。"""
    rule = _rule_by_id(rules, "RULE-002")
    out: list[dict[str, Any]] = []
    limits = rules.get("limits") or {}
    ttl_min = int(limits.get("ttl_min_seconds", 60))
    ttl_max = int(limits.get("ttl_max_seconds", 86400))
    ttl = _get_ttl_seconds(strategy)
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype not in (rule.get("applies_to_actions") or []):
            continue
        if not _affects_production_path(act, strategy, rules):
            continue
        if ttl is None:
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=(
                        f"{atype} affects production path but strategy.ttl is missing"
                    ),
                )
            )
        elif ttl < ttl_min or ttl > ttl_max:
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=(
                        f"{atype} affects production path but ttl={ttl}s "
                        f"is outside [{ttl_min}, {ttl_max}]"
                    ),
                )
            )
    return out


def _check_rule_003_high_risk_rollback(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-003：高风险动作必须有完整的 rollback_plan。"""
    rule = _rule_by_id(rules, "RULE-003")
    out: list[dict[str, Any]] = []
    high_risk = set(rules.get("high_risk_actions") or [])
    rb = _get_rollback_plan(strategy)
    rb_steps = rb.get("steps") if rb else None
    rb_trig = rb.get("triggerCondition") if rb else None
    rb_trig = rb_trig or (rb.get("trigger_condition") if rb else None)
    has_rollback = bool(rb and isinstance(rb_steps, list) and rb_steps and rb_trig)
    if has_rollback:
        return out
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype not in high_risk:
            continue
        if not rb:
            msg = f"high-risk {atype} action has no rollback_plan"
        elif not (isinstance(rb_steps, list) and rb_steps):
            msg = f"high-risk {atype} action has empty rollback_plan.steps"
        elif not rb_trig:
            msg = f"high-risk {atype} action has no rollback_plan.triggerCondition"
        else:
            msg = f"high-risk {atype} action has incomplete rollback_plan"
        out.append(
            _make_violation(
                rule,
                action_index=i,
                action_type=atype,
                target=_get_action_target(act),
                message=msg,
            )
        )
    return out


def _check_rule_004_k8s_min_replicas(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-004：K8s 扩缩容不能低于 min_replicas。"""
    rule = _rule_by_id(rules, "RULE-004")
    out: list[dict[str, Any]] = []
    min_rep = int((rules.get("limits") or {}).get("k8s_min_replicas", 2))
    applies = set(rule.get("applies_to_actions") or [])
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        params = _get_action_params(act)
        # 触发条件：声明的 SCALE_PROTECTION，或任意带 replicas 参数的 action
        if atype not in applies and "replicas" not in params:
            continue
        if "replicas" not in params:
            # 是 SCALE_PROTECTION 但没填 replicas：也按违规处理
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=f"{atype} missing parameters.replicas",
                )
            )
            continue
        try:
            rep = int(params["replicas"])
        except (TypeError, ValueError):
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=f"{atype} parameters.replicas must be integer",
                )
            )
            continue
        if rep < min_rep:
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=(
                        f"{atype} replicas={rep} is below required min={min_rep}"
                    ),
                )
            )
    return out


def _check_rule_005_waf_block_target(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-005：WAF block/deny 必须指定 path/ip/user_agent/rule_id/pattern。"""
    rule = _rule_by_id(rules, "RULE-005")
    out: list[dict[str, Any]] = []
    block_actions = set(rule.get("block_actions") or ["block", "deny"])
    required_any = rule.get("required_any_of") or [
        "path", "ip", "user_agent", "rule_id", "pattern"
    ]
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype != "APPLY_WAF_RULE":
            continue
        params = _get_action_params(act)
        # 当 parameters.action 缺失时按 "block" 处理（WAF 默认就是阻断模式）
        waf_action = str(params.get("action") or "block").lower()
        if waf_action not in block_actions:
            continue
        if not any(params.get(k) for k in required_any):
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=(
                        "WAF block rule must specify at least one of "
                        f"{required_any} in parameters"
                    ),
                )
            )
    return out


def _check_rule_006_firewall_5tuple(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-006：Firewall deny/drop 必须含 source/destination/port/protocol。"""
    rule = _rule_by_id(rules, "RULE-006")
    out: list[dict[str, Any]] = []
    block_actions = set(rule.get("block_actions") or ["deny", "drop", "block"])
    required = rule.get("required_all_of") or ["source", "destination", "port", "protocol"]
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype != "APPLY_FIREWALL_RULE":
            continue
        params = _get_action_params(act)
        # 缺省 action 时按 deny 处理
        fw_action = str(params.get("action") or "deny").lower()
        if fw_action not in block_actions:
            continue
        missing = [k for k in required if not params.get(k)]
        if missing:
            out.append(
                _make_violation(
                    rule,
                    action_index=i,
                    action_type=atype,
                    target=_get_action_target(act),
                    message=(
                        "Firewall deny rule missing required parameters: "
                        f"{', '.join(missing)}"
                    ),
                )
            )
    return out


def _check_rule_007_critical_human_approval(
    strategy: dict[str, Any], rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """RULE-007：critical 资产相关动作必须显式 human_approval=true。"""
    rule = _rule_by_id(rules, "RULE-007")
    out: list[dict[str, Any]] = []
    if _get_human_approval_flag(strategy):
        return out
    crit_idx = _index_critical_assets(rules)
    applies = set(rule.get("applies_to_actions") or [])
    for i, act in enumerate(_get_actions(strategy)):
        atype = _get_action_type(act)
        if atype not in applies:
            continue
        target = _get_action_target(act)
        hit, info = _is_critical_target(target, _scope_assets(strategy), crit_idx)
        if not hit:
            continue
        out.append(
            _make_violation(
                rule,
                action_index=i,
                action_type=atype,
                target=target,
                message=(
                    f"{atype} touches critical asset "
                    f"{info.get('asset_id') if info else target} "
                    f"but human_approval flag is not set"
                ),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Suggestions（基于 violation 反推安全建议）
# ---------------------------------------------------------------------------


def _suggestion_for(violation: dict[str, Any]) -> dict[str, Any]:
    """根据 violation 类型生成可执行的安全策略建议。"""
    rid = violation.get("rule_id")
    base = {
        "rule_id": rid,
        "title": "",
        "detail": violation.get("remediation", ""),
        "patch": {},
    }
    aidx = violation.get("action_index")
    atype = violation.get("action_type", "")
    target = violation.get("target", "")

    if rid == "RULE-001":
        base["title"] = "Constrain critical-database action scope"
        base["patch"] = {
            "field": f"actions[{aidx}].parameters",
            "operation": "merge",
            "value": {
                "scope": "ingress_only",
                "allowlistedFlows": ["DMZ_TO_DATABASE", "INTERNAL_TO_DATABASE"],
            },
        }
    elif rid == "RULE-002":
        base["title"] = "Add or fix TTL for production-path action"
        base["patch"] = {
            "field": "ttl",
            "operation": "set",
            "value": 1800,
        }
    elif rid == "RULE-003":
        base["title"] = "Add rollback plan for high-risk action"
        base["patch"] = {
            "field": "rollbackPlan",
            "operation": "set",
            "value": {
                "planId": "rb-auto",
                "steps": [
                    "remove_temporary_rules",
                    "restore_network_policy",
                    "verify_business_path_recovery",
                ],
                "triggerCondition": "false_positive_confirmed_or_business_impact_detected",
            },
        }
    elif rid == "RULE-004":
        base["title"] = "Increase replicas to satisfy minimum"
        base["patch"] = {
            "field": f"actions[{aidx}].parameters.replicas",
            "operation": "set",
            "value": 2,
        }
    elif rid == "RULE-005":
        base["title"] = "Narrow WAF rule with concrete matcher"
        base["patch"] = {
            "field": f"actions[{aidx}].parameters",
            "operation": "merge",
            "value": {
                "path": target or "/api/*",
                "rule_id": "auto-generated-rule-id",
            },
        }
    elif rid == "RULE-006":
        base["title"] = "Provide full 5-tuple for firewall deny"
        base["patch"] = {
            "field": f"actions[{aidx}].parameters",
            "operation": "merge",
            "value": {
                "source": "<source-cidr-or-asset>",
                "destination": target or "<destination-asset>",
                "port": 443,
                "protocol": "tcp",
            },
        }
    elif rid == "RULE-007":
        base["title"] = "Require human approval for critical-asset action"
        base["patch"] = {
            "field": "metadata.human_approval",
            "operation": "set",
            "value": True,
        }
    else:
        base["title"] = f"Address {rid}: {violation.get('rule_name', '')}"
    return base


# ---------------------------------------------------------------------------
# 公共 API：四个对应 MCP tool 的入口
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    return {
        "valid": True,
        "violations": [],
        "warnings": [],
        "requires_human_approval": False,
        "suggestions": [],
    }


def validate_strategy(
    strategy: Any, rules: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """跑全部 7 条规则，返回完整 5 字段结构。

    业务约定：``violations`` 与 ``warnings`` 区分如下：
        * ``severity in {critical, high}`` → violations（且 valid=False）
        * ``severity in {medium, low}`` → warnings（valid 不被它降为 False）

    ``requires_human_approval`` 仅当命中 RULE-001 / RULE-007 之一（即关键
    资产动作）时为 True，无论是否提供 ``human_approval`` 标记，因为这
    是给上游"是否需要走人工审批"的信号。
    """
    strategy = _ensure_dict(strategy)
    rules = get_rules(rules)
    result = _empty_result()

    all_findings: list[dict[str, Any]] = []
    for fn in (
        _check_rule_001_critical_db_full_block,
        _check_rule_002_production_path_ttl,
        _check_rule_003_high_risk_rollback,
        _check_rule_004_k8s_min_replicas,
        _check_rule_005_waf_block_target,
        _check_rule_006_firewall_5tuple,
        _check_rule_007_critical_human_approval,
    ):
        all_findings.extend(fn(strategy, rules))

    for f in all_findings:
        sev = str(f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            result["violations"].append(f)
        else:
            result["warnings"].append(f)

    result["valid"] = len(result["violations"]) == 0

    # 是否需要人工审批：RULE-001 / RULE-007 命中 或 critical 资产被强制操作
    needs_human = any(
        f["rule_id"] in ("RULE-001", "RULE-007") for f in all_findings
    )
    # 即便 RULE-007 通过（已显式声明 human_approval=true），下游仍把这里
    # 标为 True 时 require_human_approval tool 会单独判断"是否已声明"
    if not needs_human:
        # 兜底：扫描一遍 critical 资产命中情况
        crit_idx = _index_critical_assets(rules)
        for act in _get_actions(strategy):
            atype = _get_action_type(act)
            if atype in (rules.get("high_risk_actions") or []):
                hit, _ = _is_critical_target(
                    _get_action_target(act), _scope_assets(strategy), crit_idx
                )
                if hit:
                    needs_human = True
                    break
    result["requires_human_approval"] = needs_human

    # suggestions：每条 violation/warning 都给一条
    for f in all_findings:
        result["suggestions"].append(_suggestion_for(f))
    return result


def check_business_constraints(
    strategy: Any, rules: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """专注业务影响相关的规则（RULE-001 / 002 / 005 / 006）。

    把那些影响"业务路径 / 关键资产 / 过宽阻断"的规则挑出来单独跑，便于
    Coordinator 在最终决策前做"是否会误伤业务"的轻量复核。
    """
    strategy = _ensure_dict(strategy)
    rules = get_rules(rules)
    result = _empty_result()

    business_findings: list[dict[str, Any]] = []
    business_findings.extend(_check_rule_001_critical_db_full_block(strategy, rules))
    business_findings.extend(_check_rule_002_production_path_ttl(strategy, rules))
    business_findings.extend(_check_rule_005_waf_block_target(strategy, rules))
    business_findings.extend(_check_rule_006_firewall_5tuple(strategy, rules))

    for f in business_findings:
        sev = str(f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            result["violations"].append(f)
        else:
            result["warnings"].append(f)
    result["valid"] = len(result["violations"]) == 0

    # 业务约束维度也提供 suggestions
    for f in business_findings:
        result["suggestions"].append(_suggestion_for(f))

    # 业务规则不直接判定 human_approval（那是 RULE-007 的职责），但把
    # RULE-001 命中时的 human_approval 信号透传，方便下游集中判断
    result["requires_human_approval"] = any(
        f["rule_id"] == "RULE-001" for f in business_findings
    )
    return result


def require_human_approval(
    strategy: Any, rules: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """专门判定"是否需要人工审批"。

    判定逻辑：
      1. 若 strategy 已显式声明 human_approval=true 且未触发 RULE-001 → False
         （已经过人工评估，无需再次升级）
      2. 否则当 RULE-001 或 RULE-007 命中时 → True
      3. 任何高风险动作命中关键资产时 → True
    """
    strategy = _ensure_dict(strategy)
    rules = get_rules(rules)
    result = _empty_result()

    rule001_hits = _check_rule_001_critical_db_full_block(strategy, rules)
    rule007_hits = _check_rule_007_critical_human_approval(strategy, rules)

    # RULE-007 命中说明"关键资产被动且未声明审批" → 必须人工
    if rule007_hits:
        result["requires_human_approval"] = True
        result["violations"].extend(rule007_hits)
        for f in rule007_hits:
            result["suggestions"].append(_suggestion_for(f))

    # RULE-001 命中无论是否声明审批都应升级（涉及 critical DB 全量阻断）
    if rule001_hits:
        result["requires_human_approval"] = True
        result["violations"].extend(rule001_hits)
        for f in rule001_hits:
            result["suggestions"].append(_suggestion_for(f))

    # 已显式声明 human_approval 且未命中以上两条 → 不再升级
    if not rule001_hits and not rule007_hits and _get_human_approval_flag(strategy):
        result["requires_human_approval"] = False
    elif not rule001_hits and not rule007_hits:
        # 兜底：仅当"真破坏性动作"直接 target high 级资产时才升级人工。
        # 这里刻意不扫 scope.assets，也不覆盖 APPLY_FIREWALL_RULE / APPLY_WAF_RULE
        # 这种已经做精细化 5 元组的动作，否则一个合法的精细 firewall 策略只要
        # scope 里出现 high 级网关资产就会被错判为需要审批。
        destructive = {
            "BLOCK_IP",
            "BLOCK_DOMAIN",
            "ISOLATE_HOST",
            "ISOLATE_POD",
            "DISABLE_ACCOUNT",
            "REVOKE_TOKEN",
        }
        crit_idx = _index_critical_assets(rules)
        matched: tuple[int, dict[str, Any], dict[str, Any], str] | None = None
        for idx, act in enumerate(_get_actions(strategy)):
            atype = _get_action_type(act)
            if atype not in destructive:
                continue
            info = crit_idx.get(_get_action_target(act))
            if info and str(info.get("criticality", "")).lower() == "high":
                matched = (idx, act, info, atype)
                break
        if matched:
            idx, act, info, atype = matched
            result["requires_human_approval"] = True
            result["warnings"].append(
                {
                    "rule_id": "RULE-007",
                    "rule_name": "high_severity_asset_advisory",
                    "severity": "medium",
                    "action_index": idx,
                    "action_type": atype,
                    "target": _get_action_target(act),
                    "message": (
                        f"{atype} touches HIGH-criticality asset "
                        f"{info.get('asset_id', '')}; human review recommended"
                    ),
                    "remediation": "Consider setting metadata.human_approval=true",
                }
            )

    result["valid"] = len(result["violations"]) == 0
    return result


def suggest_safer_strategy(
    strategy: Any, rules: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """生成一组安全建议（不修改 strategy，仅返回 patch 提示）。

    返回：
      * ``suggestions[]``：每条违规对应的可执行补丁
      * ``violations[]`` / ``warnings[]``：复用 validate_strategy 的结果，
        便于消费者直接拼成"违规 → 建议"的双栏视图
    """
    full = validate_strategy(strategy, rules)
    # 整体结构与 spec 一致；suggestions 已在 validate_strategy 中计算
    return {
        "valid": full["valid"],
        "violations": full["violations"],
        "warnings": full["warnings"],
        "requires_human_approval": full["requires_human_approval"],
        "suggestions": full["suggestions"],
    }
