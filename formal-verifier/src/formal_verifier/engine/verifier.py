from __future__ import annotations

from formal_verifier.engine.continuity_checker import ContinuityChecker
from formal_verifier.engine.rule_engine import StaticRuleEngine
from formal_verifier.models import DefenseStrategy, VerificationResult
from formal_verifier.providers import verify_with_opa, verify_with_z3


class StrategyVerifier:
    """规则引擎主入口，预留 Z3/OPA 扩展点。"""

    def __init__(
        self,
        rule_engine: StaticRuleEngine | None = None,
        continuity_checker: ContinuityChecker | None = None,
    ) -> None:
        self.rule_engine = rule_engine or StaticRuleEngine()
        self.continuity_checker = continuity_checker or ContinuityChecker()

    def verify(self, strategy: DefenseStrategy) -> VerificationResult:
        violations, warnings, fixes = self.rule_engine.evaluate(strategy)
        continuity_violations, continuity_warnings, continuity_fixes = self.continuity_checker.evaluate(strategy)
        violations.extend(continuity_violations)
        warnings.extend(continuity_warnings)
        fixes.extend(continuity_fixes)

        # 预留扩展: 当前先调用占位 provider，不影响主判定
        _ = verify_with_z3(strategy.model_dump(mode="json"))
        _ = verify_with_opa(strategy.model_dump(mode="json"))

        passed = len(violations) == 0
        reason = "PASSED" if passed else "STATIC_OR_CONTINUITY_RULES_FAILED"
        return VerificationResult(
            passed=passed,
            violatedConstraints=violations,
            warnings=warnings,
            reason=reason,
            suggestedFixes=fixes,
        )

