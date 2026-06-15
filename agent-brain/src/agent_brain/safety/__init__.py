"""Safety package - layered guardrails for the OPS agent.

Three independent guardrails live here:

* :mod:`agent_brain.safety.intent_validator` - command-pattern engine
  (BLOCK / REQUIRE_APPROVAL / ALLOW) backed by the immutable rule
  catalogue in :mod:`agent_brain.safety.intent_rules`.
* :mod:`agent_brain.safety.system_config_guard` - path engine that
  refuses any write to critical OS configuration files
  (``/etc/passwd``, ``/etc/shadow``, ``/etc/sudoers``, ``/boot/*``,
  ``/lib/modules/*``, ...).
* :mod:`agent_brain.safety.prompt_injection_guard` - rule-based
  detector for prompt-injection / jailbreak attempts.

The package has no FastAPI / network / LLM dependencies and is safe to
import from any module in agent-brain.
"""
from agent_brain.safety import danger_catalogue, prompt_injection_guard, system_config_guard
from agent_brain.safety.intent_rules import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_RANK,
    DECISION_REQUIRE_APPROVAL,
    IntentRule,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_RANK,
    RULES,
    get_rules,
)
from agent_brain.safety.intent_validator import (
    IntentValidator,
    validate_intent,
)
from agent_brain.safety.prompt_injection_guard import (
    InjectionEnvelope,
    MatchedInjection,
    inspect as inspect_prompt_injection,
)
from agent_brain.safety.system_config_guard import (
    ConfigGuardEnvelope,
    MatchedPath,
    evaluate as evaluate_system_config,
)

__all__ = [
    "DECISION_ALLOW",
    "DECISION_BLOCK",
    "DECISION_REQUIRE_APPROVAL",
    "DECISION_RANK",
    "RISK_CRITICAL",
    "RISK_HIGH",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_RANK",
    "IntentRule",
    "RULES",
    "get_rules",
    "IntentValidator",
    "validate_intent",
    "ConfigGuardEnvelope",
    "MatchedPath",
    "evaluate_system_config",
    "InjectionEnvelope",
    "MatchedInjection",
    "inspect_prompt_injection",
    "system_config_guard",
    "prompt_injection_guard",
]
