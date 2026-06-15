from __future__ import annotations

import os
from typing import Any

import httpx

from agent_brain.models import DefenseStrategy


# High-risk action types that require both rollback_plan and ttl. Kept in
# sync with the same constant in mcp-servers/actuator-mcp-server so the
# in-process pre-check has identical semantics to the MCP one.
_HIGH_RISK_ACTIONS: frozenset[str] = frozenset(
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


def _has_high_risk_action(payload: dict[str, Any]) -> bool:
    for action in payload.get("actions") or []:
        if not isinstance(action, dict):
            continue
        t = action.get("type")
        if isinstance(t, str) and t.upper() in _HIGH_RISK_ACTIONS:
            return True
    return False


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class ActuatorClient:
    """Thin HTTP client to actuator-service.

    Endpoint contract (see autonomous-defense-system/actuator-service):
      POST /api/strategies/execute            -> ApiResponse<ExecutionRecord>
      POST /api/strategies/{id}/rollback      -> ApiResponse<ExecutionRecord>
      GET  /api/executions                    -> ApiResponse<List<ExecutionRecord>>
      GET  /api/executions/{id}               -> ApiResponse<ExecutionRecord>

    Responses are wrapped as ``{success, code, message, data, timestamp}``.
    This client unwraps ``data`` for callers, while preserving a fallback
    payload when the service is unreachable so the agent workflow keeps
    running.

    Before each HTTP call the client also runs the actuator-MCP pre-check
    (rollback plan / TTL / status / dry-run signalling) so a strategy is
    never submitted to the Java actuator without the same safety contract
    that mcp-servers/actuator-mcp-server enforces. The pre-check can be
    disabled via ACTUATOR_MCP_GUARD_ENABLED=false for fully off-line tests.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        failure_mode: str | None = None,
        guard_enabled: bool | None = None,
        default_dry_run: bool | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("ACTUATOR_SERVICE_BASE_URL") or "http://localhost:8081").rstrip("/")
        self.timeout = timeout if timeout is not None else float(os.environ.get("ACTUATOR_SERVICE_TIMEOUT_SECONDS", "5.0"))
        mode = (failure_mode or os.environ.get("AGENT_BRAIN_FAILURE_MODE", "compat")).strip().lower()
        self.strict_mode = mode in {"strict", "production", "prod"}
        self.guard_enabled = (
            guard_enabled
            if guard_enabled is not None
            else _env_bool("ACTUATOR_MCP_GUARD_ENABLED", True)
        )
        # Default to dry-run unless explicitly opted out, so an upstream that
        # forgets to set the flag still cannot trigger a real apply.
        self.default_dry_run = (
            default_dry_run
            if default_dry_run is not None
            else _env_bool("ACTUATOR_DEFAULT_DRY_RUN", True)
        )

    def submit_strategy(self, strategy: DefenseStrategy, *, dry_run: bool | None = None) -> dict:
        payload = self._build_strategy_request(strategy)
        effective_dry_run = self.default_dry_run if dry_run is None else bool(dry_run)
        payload["dryRun"] = effective_dry_run

        if self.guard_enabled:
            violations, warnings = self._pre_execute_check(payload)
            if violations:
                return {
                    "status": "BLOCKED",
                    "message": "actuator MCP pre-check blocked execution",
                    "strategyId": strategy.strategyId,
                    "dryRun": effective_dry_run,
                    "preCheck": {
                        "violations": violations,
                        "warnings": warnings,
                    },
                }
            warnings_for_response = warnings
        else:
            warnings_for_response = []
        try:
            response = httpx.post(
                f"{self.base_url}/api/strategies/execute",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            unwrapped = self._unwrap(response.json())
            if isinstance(unwrapped, dict):
                unwrapped.setdefault("dryRun", effective_dry_run)
                if warnings_for_response:
                    unwrapped.setdefault("preCheckWarnings", warnings_for_response)
            return unwrapped
        except Exception as exc:
            if self.strict_mode:
                return {
                    "status": "FAILED",
                    "message": f"actuator-service unavailable: {exc.__class__.__name__}",
                    "strategyId": strategy.strategyId,
                    "strictMode": True,
                    "dryRun": effective_dry_run,
                    "preCheckWarnings": warnings_for_response,
                }
            return {
                "status": "SIMULATED",
                "message": f"actuator-service unavailable: {exc.__class__.__name__}",
                "strategyId": strategy.strategyId,
                "dryRun": effective_dry_run,
                "preCheckWarnings": warnings_for_response,
            }

    @staticmethod
    def _build_strategy_request(strategy: DefenseStrategy) -> dict[str, Any]:
        body = strategy.model_dump(mode="json")
        return {
            "strategyId": body["strategyId"],
            "threatType": body["threatType"],
            "targetLayer": body["targetLayer"],
            "actions": body.get("actions", []),
            "scope": body.get("scope") or {},
            "ttl": body.get("ttl"),
            "rollbackPlan": body.get("rollbackPlan"),
        }

    @staticmethod
    def _pre_execute_check(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Mirror of actuator-mcp-server._pre_execute_check.

        Returns ``(violations, warnings)``. Violations block execution; warnings
        are surfaced on the response so the operator can spot a missing TTL
        or rollback_plan even when the strategy passes.
        """
        violations: list[str] = []
        warnings: list[str] = []

        if not payload.get("actions"):
            violations.append("actions[] is empty; strategy has nothing to apply")

        has_high_risk = _has_high_risk_action(payload)
        if not payload.get("rollbackPlan"):
            if has_high_risk:
                violations.append(
                    "rollbackPlan missing for high-risk action; refusing to execute without rollback"
                )
            else:
                warnings.append("rollbackPlan missing; auto-rollback will be unavailable")

        ttl = payload.get("ttl")
        if ttl in (None, 0):
            if has_high_risk:
                violations.append(
                    "ttl missing/zero for high-risk action; refusing to execute without TTL"
                )
            else:
                warnings.append("ttl missing/zero; defense action will not auto-expire")
        return violations, warnings

    @staticmethod
    def _unwrap(body: Any) -> dict:
        if isinstance(body, dict) and "data" in body and "success" in body:
            data = body.get("data")
            if isinstance(data, dict):
                return data
            return {"data": data, "message": body.get("message"), "code": body.get("code")}
        if isinstance(body, dict):
            return body
        return {"data": body}

    @staticmethod
    def _unwrap(body: Any) -> dict:
        if isinstance(body, dict) and "data" in body and "success" in body:
            data = body.get("data")
            if isinstance(data, dict):
                return data
            return {"data": data, "message": body.get("message"), "code": body.get("code")}
        if isinstance(body, dict):
            return body
        return {"data": body}

