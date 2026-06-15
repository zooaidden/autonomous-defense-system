from __future__ import annotations

import os
from typing import Any

import httpx

from agent_brain.models import DefenseStrategy, VerificationResult


class FormalVerifierClient:
    """HTTP client for formal-verifier.

    Contract (see autonomous-defense-system/formal-verifier):
      POST /verify  -> request body is the ``DefenseStrategy`` JSON itself,
                       response body is a ``VerificationResult`` whose
                       ``violatedConstraints``/``warnings`` are lists of
                       ``ConstraintIssue`` objects (``code/description/severity``).

    agent-brain's local ``VerificationResult`` keeps those two lists as plain
    strings, so this client flattens ``ConstraintIssue`` into
    ``"[CODE] description"`` strings before constructing the model.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        failure_mode: str | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("FORMAL_VERIFIER_BASE_URL") or "http://localhost:8002").rstrip("/")
        self.timeout = timeout if timeout is not None else float(os.environ.get("FORMAL_VERIFIER_TIMEOUT_SECONDS", "5.0"))
        mode = (failure_mode or os.environ.get("AGENT_BRAIN_FAILURE_MODE", "compat")).strip().lower()
        self.strict_mode = mode in {"strict", "production", "prod"}

    def verify(self, strategy: DefenseStrategy) -> VerificationResult:
        try:
            response = httpx.post(
                f"{self.base_url}/verify",
                json=strategy.model_dump(mode="json"),
                timeout=self.timeout,
            )
            response.raise_for_status()
            return self._parse_response(response.json())
        except Exception as exc:
            if self.strict_mode:
                return VerificationResult(
                    passed=False,
                    violatedConstraints=[],
                    warnings=[f"formal-verifier unavailable ({exc.__class__.__name__})"],
                    reason="VERIFIER_UNAVAILABLE_STRICT",
                    suggestedFixes=["Restore formal-verifier service before retrying workflow execution."],
                )
            return VerificationResult(
                passed=True,
                violatedConstraints=[],
                warnings=[f"formal-verifier unavailable ({exc.__class__.__name__}), fallback accepted"],
                reason="FALLBACK_ACCEPT",
                suggestedFixes=[],
            )

    @staticmethod
    def _parse_response(data: Any) -> VerificationResult:
        if not isinstance(data, dict):
            return VerificationResult(
                passed=False,
                violatedConstraints=[],
                warnings=[f"unexpected verifier response type: {type(data).__name__}"],
                reason="INVALID_RESPONSE",
                suggestedFixes=[],
            )
        return VerificationResult(
            passed=bool(data.get("passed", False)),
            violatedConstraints=FormalVerifierClient._flatten_issues(data.get("violatedConstraints")),
            warnings=FormalVerifierClient._flatten_issues(data.get("warnings")),
            reason=str(data.get("reason", "UNKNOWN")),
            suggestedFixes=[str(fix) for fix in data.get("suggestedFixes", []) if fix is not None],
        )

    @staticmethod
    def _flatten_issues(items: Any) -> list[str]:
        if not isinstance(items, list):
            return []
        flattened: list[str] = []
        for item in items:
            if isinstance(item, dict):
                code = item.get("code", "")
                description = item.get("description", "")
                if code and description:
                    flattened.append(f"[{code}] {description}")
                elif code:
                    flattened.append(str(code))
                elif description:
                    flattened.append(str(description))
            elif item is not None:
                flattened.append(str(item))
        return flattened

