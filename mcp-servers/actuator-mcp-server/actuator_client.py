"""actuator-mcp-server 的纯 Python 业务层。

把对 Spring Boot ``actuator-service`` 的 REST 调用、安全检查、mock 模式都
集中在这里；``server.py`` 只做协议层薄壳，方便单元测试 + 替换底层实现。

接口契约（与 ``actuator-service/StrategyController`` 一一对应）::

    POST /api/strategies/execute            -> ApiResponse<ExecutionRecord>
    POST /api/strategies/{id}/rollback      -> ApiResponse<ExecutionRecord>
    GET  /api/executions                    -> ApiResponse<List<ExecutionRecord>>
    GET  /api/executions/{id}               -> ApiResponse<ExecutionRecord>

环境变量::

    ACTUATOR_BASE_URL        actuator-service 根地址，默认 http://localhost:8081
                             （与 actuator-service/application.yml 的 server.port=8081 对齐）
    ACTUATOR_MODE            real / mock，默认 real。real 模式下若目标服务不可达，
                             会自动降级返回 mock 结果，方便前端演示。
    ACTUATOR_HTTP_TIMEOUT    单次 HTTP 调用超时秒数，默认 5

返回信封统一为::

    {"success": true,  "data": ..., "message": "..."}
    {"success": false, "data": null, "message": "..."}
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Iterable

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 常量与默认值
# ---------------------------------------------------------------------------

# 业务模式
MODE_REAL = "real"
MODE_MOCK = "mock"

# actuator-service 默认地址。环境变量优先级最高；构造参数次之；默认垫底。
DEFAULT_BASE_URL = "http://localhost:8081"
DEFAULT_TIMEOUT_SECONDS = 5.0

# 高风险动作集合：缺少 rollback_plan 或 ttl 时会被拒绝执行。
# 与 agent_brain.models.ActionType 中明显具有阻断/隔离/账号回收语义的项保持一致。
_HIGH_RISK_ACTIONS = frozenset(
    {
        "BLOCK_IP",
        "BLOCK_DOMAIN",
        "RESTRICT_EGRESS",
        "ISOLATE_HOST",
        "ISOLATE_POD",
        "DISABLE_ACCOUNT",
        "REVOKE_TOKEN",
    }
)

# Coordinator 接受执行的唯一 status；其它一律拒绝。
_STATUS_APPROVED = "approved_for_execution"

# 人工审批边界拒绝时使用的固定 message，前端 / API 都依赖这个文案。
_HUMAN_APPROVAL_BLOCK_MESSAGE = (
    "Strategy requires human approval and cannot be executed automatically."
)


class ActuatorClientError(Exception):
    """业务可恢复异常：不会越过 server.py 抛到 MCP 客户端。"""


# ---------------------------------------------------------------------------
# 工具函数：环境变量解析 + 信封封装
# ---------------------------------------------------------------------------


def _ok(data: Any, message: str = "ok") -> dict[str, Any]:
    """构造统一的成功响应。"""
    return {"success": True, "data": data, "message": message}


def _err(message: str, *, data: Any = None) -> dict[str, Any]:
    """构造统一的失败响应；data 默认 None，但允许携带预检结构。"""
    return {"success": False, "data": data, "message": message}


def _env_str(name: str, default: str) -> str:
    """读取字符串环境变量；空串视为未设置。"""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip()


def _env_float(name: str, default: float) -> float:
    """读取浮点环境变量；解析失败时回退默认。"""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("invalid %s=%r, falling back to %s", name, raw, default)
        return default


# ---------------------------------------------------------------------------
# 安全检查：在真正发起 HTTP 调用前做的策略守门
# ---------------------------------------------------------------------------


def _normalize_strategy(strategy: Any) -> dict[str, Any]:
    """把上游传入的 strategy 标准化为 dict；非 dict 直接抛错。"""
    if not isinstance(strategy, dict):
        raise TypeError(f"strategy must be a dict, got {type(strategy).__name__}")
    return strategy


def _resolve_human_approval_flag(strategy: dict[str, Any]) -> bool:
    """从多处兼容字段中解析 ``human_approval_required``。

    Coordinator 的输出会同时把这个标志挂在策略本体（snake_case）和
    metadata.human_approval（旧约定）两处；这里两处都看，宽松匹配。
    """
    if bool(strategy.get("human_approval_required")):
        return True
    metadata = strategy.get("metadata") or {}
    if isinstance(metadata, dict) and bool(metadata.get("human_approval")):
        return True
    return False


def _resolve_auto_execution_flag(strategy: dict[str, Any]) -> bool | None:
    """从策略中解析 ``auto_execution_allowed``。

    返回值含义：
      - True:  Coordinator 明确允许自动执行
      - False: Coordinator 明确禁止自动执行（必须走人工审批通道）
      - None:  策略中没有该字段（旧版策略 / 旁路调用），由调用方决定如何处理

    与 ``human_approval_required`` 的关系：本函数只看 ``auto_execution_allowed``
    这个独立信号，最终的拒绝判定由 :func:`_check_human_approval_boundary`
    把两个信号综合起来。
    """
    if "auto_execution_allowed" not in strategy:
        return None
    raw = strategy.get("auto_execution_allowed")
    if isinstance(raw, bool):
        return raw
    return None


def _check_human_approval_boundary(strategy: dict[str, Any]) -> tuple[bool, str | None]:
    """人工审批边界守门：execute_strategy 进入预检前的最优先检查。

    返回 ``(blocked, reason)``：
      - blocked=True 表示必须立刻拒绝执行（不允许进入后续检查 / HTTP 调用）
      - reason 仅作日志使用，对外 message 一律使用统一的
        ``_HUMAN_APPROVAL_BLOCK_MESSAGE``

    触发条件（任一即拒绝）：
      1. ``auto_execution_allowed`` 显式为 False
      2. ``human_approval_required`` 为 True
    """
    if _resolve_auto_execution_flag(strategy) is False:
        return True, "auto_execution_allowed=false"
    if _resolve_human_approval_flag(strategy):
        return True, "human_approval_required=true"
    return False, None


def _resolve_status(strategy: dict[str, Any]) -> str | None:
    """读取策略状态；不存在时返回 None（与 ``approved_for_execution`` 区分）。"""
    raw = strategy.get("status")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().lower()
    return None


def _resolve_ttl_seconds(strategy: dict[str, Any]) -> int | None:
    """从 ``ttl`` / ``ttl_minutes`` / ``ttlMinutes`` 中解析出 TTL 秒数。

    - ``ttl`` 默认按秒处理（与 actuator-service DefenseStrategyRequest.ttl 一致）
    - ``ttl_minutes`` / ``ttlMinutes`` 按分钟换算
    - 任何非正数或非数字都视为缺失
    """
    raw_seconds = strategy.get("ttl")
    if isinstance(raw_seconds, (int, float)) and raw_seconds > 0:
        return int(raw_seconds)

    for key in ("ttl_minutes", "ttlMinutes"):
        raw_minutes = strategy.get(key)
        if isinstance(raw_minutes, (int, float)) and raw_minutes > 0:
            return int(raw_minutes) * 60
    return None


def _resolve_rollback_plan(strategy: dict[str, Any]) -> dict[str, Any] | None:
    """读取 rollback 计划；要求至少包含可识别的内容（planId 或 steps 非空）。"""
    plan = strategy.get("rollbackPlan") or strategy.get("rollback_plan")
    if not isinstance(plan, dict) or not plan:
        return None
    has_plan_id = bool(str(plan.get("planId") or plan.get("plan_id") or "").strip())
    steps = plan.get("steps") or []
    has_steps = isinstance(steps, list) and len(steps) > 0
    if has_plan_id or has_steps:
        return plan
    return None


def _iter_action_types(strategy: dict[str, Any]) -> Iterable[str]:
    """便捷地迭代策略所有 action.type（已统一大写）。"""
    actions = strategy.get("actions") or []
    if not isinstance(actions, list):
        return ()
    out: list[str] = []
    for act in actions:
        if not isinstance(act, dict):
            continue
        atype = act.get("type")
        if isinstance(atype, str) and atype.strip():
            out.append(atype.strip().upper())
    return out


def _has_high_risk_action(strategy: dict[str, Any]) -> bool:
    """是否存在任意高风险动作。"""
    return any(t in _HIGH_RISK_ACTIONS for t in _iter_action_types(strategy))


def _pre_execute_check(strategy: dict[str, Any]) -> tuple[list[str], list[str]]:
    """对 execute_strategy 进行多项安全检查（人工审批边界已在更早一步独立处理）。

    返回 ``(violations, warnings)`` 两个字符串列表：
      - violations 非空：不允许下发执行（execute_strategy 直接返回 success=False）
      - warnings 非空：允许执行但要在响应里告诉调用方
    """
    violations: list[str] = []
    warnings: list[str] = []

    # 1) status 必须是 approved_for_execution
    status = _resolve_status(strategy)
    if status is not None and status != _STATUS_APPROVED:
        violations.append(
            f"strategy.status={status!r} is not 'approved_for_execution'; refuse to execute"
        )
    elif status is None:
        # 没有 status 字段属于"上游不规范"，按 warning 提示，但不阻断
        warnings.append(
            "strategy.status is missing; recommend Coordinator output "
            "to set status='approved_for_execution' explicitly"
        )

    # 2) rollback_plan 缺失：高风险动作直接拒绝；其它给 warning
    plan = _resolve_rollback_plan(strategy)
    if plan is None:
        if _has_high_risk_action(strategy):
            violations.append(
                "rollback_plan is missing while strategy contains high-risk actions; "
                "refuse to execute without rollback"
            )
        else:
            warnings.append("rollback_plan is missing; auto-rollback will be unavailable")

    # 3) ttl_minutes 缺失：高风险动作直接拒绝；其它给 warning
    ttl_seconds = _resolve_ttl_seconds(strategy)
    if ttl_seconds is None:
        if _has_high_risk_action(strategy):
            violations.append(
                "ttl is missing while strategy contains high-risk actions; "
                "refuse to execute without TTL"
            )
        else:
            warnings.append("ttl is missing; defense action will not auto-expire")

    return violations, warnings


# ---------------------------------------------------------------------------
# REST 请求体构造：映射到 actuator-service.DefenseStrategyRequest
# ---------------------------------------------------------------------------


def _build_strategy_request(strategy: dict[str, Any]) -> dict[str, Any]:
    """裁剪上游策略为 actuator-service 期望的请求体。

    actuator-service.DefenseStrategyRequest 只接受这 7 个字段；多余字段
    （比如 status / human_approval_required / rationale 等）必须剥掉，
    以免被 Spring 校验驳回。
    """
    return {
        "strategyId": strategy.get("strategyId"),
        "threatType": strategy.get("threatType"),
        "targetLayer": strategy.get("targetLayer"),
        "actions": strategy.get("actions") or [],
        "scope": strategy.get("scope") or {},
        "ttl": _resolve_ttl_seconds(strategy),
        "rollbackPlan": _resolve_rollback_plan(strategy),
    }


def _unwrap_api_response(body: Any) -> Any:
    """把 ApiResponse<T> 中的 ``data`` 取出来；非约定形态原样返回。"""
    if isinstance(body, dict) and "success" in body and "data" in body:
        return body.get("data")
    return body


# ---------------------------------------------------------------------------
# Mock 数据生成
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _build_mock_execution_record(
    strategy: dict[str, Any],
    *,
    execution_id: str | None = None,
    status: str = "SUCCEEDED",
) -> dict[str, Any]:
    """生成与 actuator-service.ExecutionRecord 字段对齐的 mock 记录。"""
    eid = execution_id or f"exec-mock-{uuid.uuid4().hex[:8]}"
    return {
        "executionId": eid,
        "strategyId": strategy.get("strategyId") or "stg-unknown",
        "status": status,
        "startTime": _now_iso(),
        "endTime": _now_iso() if status in {"SUCCEEDED", "FAILED"} else None,
        "resultMessage": (
            "mock execution succeeded"
            if status == "SUCCEEDED"
            else f"mock execution {status.lower()}"
        ),
        "rollbackStatus": "AVAILABLE",
        "ttl": _resolve_ttl_seconds(strategy),
        "generatedArtifacts": [],
        "strategySnapshot": _build_strategy_request(strategy),
        "failureReason": None,
        "rollbackReason": None,
        "rollbackTrigger": None,
        "rollbackAt": None,
    }


def _build_mock_rollback_record(
    strategy_id: str,
    *,
    execution_id: str | None = None,
) -> dict[str, Any]:
    """生成与 actuator-service.ExecutionRecord 一致的 mock 回滚记录。"""
    eid = execution_id or f"exec-mock-{uuid.uuid4().hex[:8]}"
    return {
        "executionId": eid,
        "strategyId": strategy_id,
        "status": "SUCCEEDED",
        "startTime": _now_iso(),
        "endTime": _now_iso(),
        "resultMessage": "mock rollback completed",
        "rollbackStatus": "SUCCEEDED",
        "ttl": None,
        "generatedArtifacts": [],
        "strategySnapshot": {"strategyId": strategy_id},
        "failureReason": None,
        "rollbackReason": "manual mock rollback",
        "rollbackTrigger": "MANUAL",
        "rollbackAt": _now_iso(),
    }


# ---------------------------------------------------------------------------
# ActuatorClient：本服务对外的统一门面
# ---------------------------------------------------------------------------


class ActuatorClient:
    """actuator-service 的 Python 业务客户端。

    支持两种模式：

    * ``real``：真实通过 HTTP 调用 actuator-service。如果目标不可达，
      会自动降级到 mock 模式并在 message 里说明原因，避免演示场景中断。
    * ``mock``：完全不发起 HTTP 调用，直接返回伪造的 ExecutionRecord，
      用于前端联调或 actuator-service 没启动的场景。

    所有公共方法返回 ``{"success": bool, "data": ..., "message": ...}``。
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        mode: str | None = None,
        timeout: float | None = None,
        # 注入用：测试或 mock 透传时使用
        http_client: httpx.Client | None = None,
    ) -> None:
        # 1) 基础地址：参数 > 环境变量 > 默认 8081
        self._base_url = (
            (base_url or _env_str("ACTUATOR_BASE_URL", DEFAULT_BASE_URL))
            .rstrip("/")
        )
        # 2) 模式：参数 > 环境变量 > real
        chosen_mode = (mode or _env_str("ACTUATOR_MODE", MODE_REAL)).lower()
        if chosen_mode not in (MODE_REAL, MODE_MOCK):
            logger.warning("unknown ACTUATOR_MODE=%r, falling back to '%s'", chosen_mode, MODE_REAL)
            chosen_mode = MODE_REAL
        self._mode = chosen_mode
        # 3) 超时：参数 > 环境变量 > 5.0
        self._timeout = (
            float(timeout) if timeout is not None else _env_float("ACTUATOR_HTTP_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)
        )
        # 4) 可注入的 http client（便于测试）
        self._http_client = http_client

        logger.info(
            "ActuatorClient initialized: base_url=%s mode=%s timeout=%.1fs",
            self._base_url,
            self._mode,
            self._timeout,
        )

    # ------------------------------------------------------------------
    # 只读属性（便于测试与 server.py 上报）
    # ------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def timeout(self) -> float:
        return self._timeout

    # ------------------------------------------------------------------
    # 公共 API：execute / rollback / get / list
    # ------------------------------------------------------------------

    def execute_strategy(self, strategy: Any) -> dict[str, Any]:
        """下发执行；先做 4 项安全检查，再决定是否调用真实 API。

        返回结构在 success 时形如::

            {"success": true,
             "data": {
                 "execution_record": <ExecutionRecord>,
                 "warnings": ["..."],
                 "mode": "real" | "mock_fallback" | "mock",
                 "pre_check": {"violations": [], "warnings": [...]}
             },
             "message": "..."}

        violations 非空时，``success=False``、``data`` 给出 pre_check 详情，
        让上游清楚被拒绝的具体原因。
        """
        try:
            strategy = _normalize_strategy(strategy)
        except TypeError as exc:
            return _err(str(exc))

        # 最高优先级：人工审批边界。一旦命中立即拒绝，使用 spec 规定的统一文案，
        # 不进入后续 status/rollback/ttl 任何检查。
        blocked, block_reason = _check_human_approval_boundary(strategy)
        if blocked:
            logger.info("execute_strategy blocked by human-approval boundary: %s", block_reason)
            return _err(
                _HUMAN_APPROVAL_BLOCK_MESSAGE,
                data={
                    "execution_record": None,
                    "pre_check": {
                        "violations": [_HUMAN_APPROVAL_BLOCK_MESSAGE],
                        "warnings": [],
                    },
                    "human_approval_required": True,
                    "auto_execution_allowed": False,
                    "approval_reason": list(strategy.get("approval_reason") or []),
                    "safety_checks": list(strategy.get("safety_checks") or []),
                    "block_reason": block_reason,
                },
            )

        violations, warnings = _pre_execute_check(strategy)
        if violations:
            return _err(
                "pre-execute check failed: " + "; ".join(violations),
                data={
                    "pre_check": {"violations": violations, "warnings": warnings},
                    "execution_record": None,
                },
            )

        body = _build_strategy_request(strategy)

        # mock 模式：直接合成结果
        if self._mode == MODE_MOCK:
            record = _build_mock_execution_record(strategy)
            return _ok(
                {
                    "execution_record": record,
                    "warnings": warnings,
                    "mode": MODE_MOCK,
                    "pre_check": {"violations": [], "warnings": warnings},
                },
                f"mock execution succeeded: {record['executionId']}",
            )

        # real 模式：发起 HTTP；失败时降级 mock 并显式标记 mode=mock_fallback
        try:
            data = self._post_json("/api/strategies/execute", body)
        except (httpx.HTTPError, ActuatorClientError) as exc:
            logger.warning("execute_strategy real call failed: %s; falling back to mock", exc)
            record = _build_mock_execution_record(strategy)
            return _ok(
                {
                    "execution_record": record,
                    "warnings": warnings + [f"actuator-service unreachable: {exc}"],
                    "mode": "mock_fallback",
                    "pre_check": {"violations": [], "warnings": warnings},
                },
                f"actuator-service unavailable, returned mock execution: {record['executionId']}",
            )

        return _ok(
            {
                "execution_record": data,
                "warnings": warnings,
                "mode": MODE_REAL,
                "pre_check": {"violations": [], "warnings": warnings},
            },
            f"strategy executed: {(data or {}).get('executionId', 'unknown')}",
        )

    def rollback_strategy(self, strategy_id: str) -> dict[str, Any]:
        """触发回滚。"""
        if not isinstance(strategy_id, str) or not strategy_id.strip():
            return _err("strategy_id must be a non-empty string")
        sid = strategy_id.strip()

        if self._mode == MODE_MOCK:
            record = _build_mock_rollback_record(sid)
            return _ok(
                {"execution_record": record, "mode": MODE_MOCK},
                f"mock rollback completed: {record['executionId']}",
            )

        try:
            data = self._post_json(f"/api/strategies/{sid}/rollback", body=None)
        except (httpx.HTTPError, ActuatorClientError) as exc:
            logger.warning("rollback real call failed: %s; falling back to mock", exc)
            record = _build_mock_rollback_record(sid)
            return _ok(
                {
                    "execution_record": record,
                    "mode": "mock_fallback",
                    "warnings": [f"actuator-service unreachable: {exc}"],
                },
                f"actuator-service unavailable, returned mock rollback: {record['executionId']}",
            )

        return _ok(
            {"execution_record": data, "mode": MODE_REAL},
            f"rollback dispatched: {(data or {}).get('executionId', sid)}",
        )

    def get_execution_status(self, execution_id: str) -> dict[str, Any]:
        """查询单条执行记录的最新状态。"""
        if not isinstance(execution_id, str) or not execution_id.strip():
            return _err("execution_id must be a non-empty string")
        eid = execution_id.strip()

        if self._mode == MODE_MOCK:
            return _ok(
                {
                    "execution_record": {
                        "executionId": eid,
                        "strategyId": "stg-mock",
                        "status": "SUCCEEDED",
                        "startTime": _now_iso(),
                        "endTime": _now_iso(),
                        "resultMessage": "mock query result",
                        "rollbackStatus": "AVAILABLE",
                        "ttl": None,
                        "generatedArtifacts": [],
                        "strategySnapshot": {},
                        "failureReason": None,
                        "rollbackReason": None,
                        "rollbackTrigger": None,
                        "rollbackAt": None,
                    },
                    "mode": MODE_MOCK,
                },
                f"mock execution status returned for {eid}",
            )

        try:
            data = self._get(f"/api/executions/{eid}")
        except (httpx.HTTPError, ActuatorClientError) as exc:
            return _err(f"failed to fetch execution {eid}: {exc}")

        return _ok(
            {"execution_record": data, "mode": MODE_REAL},
            f"execution status fetched for {eid}",
        )

    def list_executions(self, limit: int = 20) -> dict[str, Any]:
        """列出最近的执行记录；本地按 ``limit`` 裁剪（actuator-service 暂未支持分页）。"""
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return _err(f"limit must be an integer, got {limit!r}")
        if limit <= 0:
            return _err("limit must be positive")

        if self._mode == MODE_MOCK:
            sample = [
                _build_mock_execution_record({"strategyId": f"stg-demo-{i}"}, status="SUCCEEDED")
                for i in range(min(limit, 3))
            ]
            return _ok(
                {"executions": sample, "count": len(sample), "mode": MODE_MOCK, "limit": limit},
                f"mock list returned {len(sample)} record(s)",
            )

        try:
            data = self._get("/api/executions")
        except (httpx.HTTPError, ActuatorClientError) as exc:
            logger.warning("list_executions real call failed: %s", exc)
            return _err(f"failed to list executions: {exc}")

        records = data if isinstance(data, list) else []
        sliced = records[:limit]
        return _ok(
            {"executions": sliced, "count": len(sliced), "mode": MODE_REAL, "limit": limit},
            f"listed {len(sliced)} execution(s) (limit={limit})",
        )

    # ------------------------------------------------------------------
    # HTTP 内部封装：可被测试 mock 注入
    # ------------------------------------------------------------------

    def _post_json(self, path: str, body: dict[str, Any] | None) -> Any:
        """POST 请求；解析 ApiResponse<T>.data。"""
        url = self._base_url + path
        if self._http_client is not None:
            response = self._http_client.post(url, json=body, timeout=self._timeout)
        else:
            response = httpx.post(url, json=body, timeout=self._timeout)
        response.raise_for_status()
        return _unwrap_api_response(response.json())

    def _get(self, path: str) -> Any:
        """GET 请求；解析 ApiResponse<T>.data。"""
        url = self._base_url + path
        if self._http_client is not None:
            response = self._http_client.get(url, timeout=self._timeout)
        else:
            response = httpx.get(url, timeout=self._timeout)
        response.raise_for_status()
        return _unwrap_api_response(response.json())


__all__ = [
    "ActuatorClient",
    "ActuatorClientError",
    "MODE_MOCK",
    "MODE_REAL",
]
