"""Command-level safety intent validator for the OPS agent.

Public surface
--------------

* :func:`validate_intent` accepts the dict-shaped contract used by the
  upcoming ``/ops/chat`` endpoint::

      {
          "instruction": "<user natural language>",
          "candidateCommands": ["<shell command>", ...],
          "candidateActions": [{"type": "...", ...}, ...]
      }

  and returns the unified envelope::

      {
          "decision": "ALLOW" | "REQUIRE_APPROVAL" | "BLOCK",
          "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
          "matchedRules": [
              {
                  "ruleId": "B-001",
                  "decision": "BLOCK",
                  "riskLevel": "CRITICAL",
                  "description": "...",
                  "matchedIn": "command" | "instruction" | "action",
                  "matchedText": "<truncated>",
                  "safeAlternative": "..." | null
              },
              ...
          ],
          "reason": "<human-readable summary>",
          "safeAlternative": "..." | null
      }

* :class:`IntentValidator` exposes the same logic via a class with a
  configurable rule catalogue (useful for tests and future extensions).

Design notes
------------

1. **Conservative by default.** When no rule matches a non-empty input,
   the validator returns ``REQUIRE_APPROVAL`` rather than ``ALLOW``.
   Unknown commands must always be reviewed by a human.

2. **Empty input is ALLOW.** If the caller provides nothing to validate
   (no instruction, no commands, no actions), the validator returns a
   benign ALLOW envelope so callers can short-circuit cleanly.

3. **Decision precedence.** ``BLOCK > REQUIRE_APPROVAL > ALLOW``. Risk
   level is the maximum across all matches.

4. **Anchored ALLOW + chain awareness.** ALLOW rules are anchored at
   the start of the (sudo-stripped) command. In addition, when a
   command contains a shell-chain operator (``|``, ``;``, ``&&``,
   ``||``, ``&``, ``>``, ``>>``, backtick, ``$( ``), ALLOW rules are
   skipped for that command so a dangerous tail (e.g.
   ``ps aux | tee /etc/passwd``) cannot inherit a safe tag.

5. **Structured actions.** Each ``candidateAction`` is best-effort
   converted into a synthetic shell command (``_stringify_action``) so
   the same regex catalogue can apply uniformly. Actions that already
   carry a ``command`` string are validated verbatim.

6. **No external dependencies.** The validator is pure-Python and is
   intentionally not wired into ``/ops/chat``; orchestration will be
   added in a follow-up phase.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from agent_brain.safety.intent_rules import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_RANK,
    DECISION_REQUIRE_APPROVAL,
    IntentRule,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_RANK,
    get_rules,
)

logger = logging.getLogger(__name__)

# Generic copy reused for default REQUIRE_APPROVAL fallbacks.
_GENERIC_APPROVAL_HINT = (
    "Get explicit human approval before executing this command."
)
_NO_RULE_MATCH_REASON = (
    "No safety rule matched; defaulting to REQUIRE_APPROVAL for human review."
)
_EMPTY_INPUT_REASON = (
    "No instruction, commands, or actions supplied; nothing to validate."
)
_NON_DICT_PAYLOAD_REASON = (
    "Payload is not a dict; rejecting for human review."
)

# Maximum length of matchedText echoed back to the caller. Long inputs
# (e.g. multi-line shell scripts) get truncated so the envelope stays
# small enough for logging / UI display.
_MATCHED_TEXT_LIMIT = 200

# Operators that turn a single command into a chained one. ALLOW rules
# are skipped for commands containing any of these so a safe prefix
# cannot vouch for an unsafe tail.
_SHELL_CHAIN_RE = re.compile(r";|&&|\|\||\||&|>>?|`|\$\(")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_intent(payload: Any) -> dict[str, Any]:
    """Validate an OPS request payload and return the decision envelope.

    The payload contract is documented at module level. Any non-dict
    input is treated as a malformed request and yields a
    ``REQUIRE_APPROVAL`` envelope so the caller never silently bypasses
    the validator.
    """
    if not isinstance(payload, dict):
        return _build_envelope(
            decision=DECISION_REQUIRE_APPROVAL,
            risk_level=RISK_MEDIUM,
            matched=[],
            reason=_NON_DICT_PAYLOAD_REASON,
            safe_alternative=_GENERIC_APPROVAL_HINT,
        )

    instruction = payload.get("instruction") or ""
    raw_commands = payload.get("candidateCommands") or []
    raw_actions = payload.get("candidateActions") or []

    commands = list(raw_commands) if isinstance(raw_commands, Iterable) and not isinstance(raw_commands, (str, bytes)) else []
    actions = list(raw_actions) if isinstance(raw_actions, Iterable) and not isinstance(raw_actions, (str, bytes)) else []

    return IntentValidator().validate(
        instruction=str(instruction),
        candidate_commands=commands,
        candidate_actions=actions,
    )


class IntentValidator:
    """Apply the rule catalogue to an OPS request.

    Most callers should use :func:`validate_intent`; this class is
    primarily for tests and for downstream code that wants to inject a
    custom rule catalogue (e.g. to add tenant-specific BLOCK rules).
    """

    def __init__(self, rules: tuple[IntentRule, ...] | None = None) -> None:
        self._rules: tuple[IntentRule, ...] = (
            tuple(rules) if rules is not None else get_rules()
        )

    def validate(
        self,
        *,
        instruction: str = "",
        candidate_commands: list[str] | None = None,
        candidate_actions: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run all rules and produce a single decision envelope."""
        instruction_text = (instruction or "").strip()

        # Pre-filter blanks so that ``["", "   "]`` is treated the same
        # as ``[]`` for the empty-input fast path.
        normalized_commands: list[str] = [
            str(c).strip() for c in (candidate_commands or []) if str(c or "").strip()
        ]
        # Pre-stringify actions and drop the ones that produce nothing.
        normalized_actions: list[tuple[dict[str, Any], str]] = []
        for action in candidate_actions or []:
            synthetic = _stringify_action(action)
            if synthetic:
                normalized_actions.append((action, synthetic))

        if not instruction_text and not normalized_commands and not normalized_actions:
            return _build_envelope(
                decision=DECISION_ALLOW,
                risk_level=RISK_LOW,
                matched=[],
                reason=_EMPTY_INPUT_REASON,
                safe_alternative=None,
            )

        matched: list[dict[str, Any]] = []

        # 1) Validate every candidate command against every rule.
        for cmd_text in normalized_commands:
            chained = bool(_SHELL_CHAIN_RE.search(cmd_text))
            for rule in self._rules:
                if rule.decision == DECISION_ALLOW and chained:
                    # Skip ALLOW for chained commands so safe prefixes
                    # cannot vouch for a dangerous tail.
                    continue
                if rule.pattern.search(cmd_text):
                    matched.append(_render_match(rule, "command", cmd_text))

        # 2) Validate structured actions (best-effort stringification).
        for _action, synthetic in normalized_actions:
            chained = bool(_SHELL_CHAIN_RE.search(synthetic))
            for rule in self._rules:
                if rule.decision == DECISION_ALLOW and chained:
                    continue
                if rule.pattern.search(synthetic):
                    matched.append(_render_match(rule, "action", synthetic))

        # 3) Validate instruction text. ALLOW rules are skipped here
        # because natural language sentences (e.g. "please show me
        # the disk usage") would otherwise short-circuit to ALLOW
        # without a verified candidate command.
        if instruction_text:
            for rule in self._rules:
                if rule.decision == DECISION_ALLOW:
                    continue
                if rule.pattern.search(instruction_text):
                    matched.append(
                        _render_match(rule, "instruction", instruction_text)
                    )

        if not matched:
            return _build_envelope(
                decision=DECISION_REQUIRE_APPROVAL,
                risk_level=RISK_MEDIUM,
                matched=[],
                reason=_NO_RULE_MATCH_REASON,
                safe_alternative=_GENERIC_APPROVAL_HINT,
            )

        decision = _max_decision(matched)
        risk_level = _max_risk(matched)
        safe_alternative = _pick_safe_alternative(matched, decision)
        reason = _build_reason(decision, matched)

        return _build_envelope(
            decision=decision,
            risk_level=risk_level,
            matched=matched,
            reason=reason,
            safe_alternative=safe_alternative,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_envelope(
    *,
    decision: str,
    risk_level: str,
    matched: list[dict[str, Any]],
    reason: str,
    safe_alternative: str | None,
) -> dict[str, Any]:
    """Assemble the final outbound envelope."""
    return {
        "decision": decision,
        "riskLevel": risk_level,
        "matchedRules": matched,
        "reason": reason,
        "safeAlternative": safe_alternative,
    }


def _render_match(rule: IntentRule, source: str, snippet: str) -> dict[str, Any]:
    """Render an :class:`IntentRule` hit as a serializable dict."""
    truncated = snippet
    if len(truncated) > _MATCHED_TEXT_LIMIT:
        truncated = truncated[: _MATCHED_TEXT_LIMIT - 3] + "..."
    return {
        "ruleId": rule.rule_id,
        "decision": rule.decision,
        "riskLevel": rule.risk_level,
        "description": rule.description,
        "matchedIn": source,
        "matchedText": truncated,
        "safeAlternative": rule.safe_alternative,
    }


def _max_decision(matched: list[dict[str, Any]]) -> str:
    return max(
        (m["decision"] for m in matched),
        key=lambda d: DECISION_RANK.get(d, 0),
    )


def _max_risk(matched: list[dict[str, Any]]) -> str:
    return max(
        (m["riskLevel"] for m in matched),
        key=lambda r: RISK_RANK.get(r, 0),
    )


def _pick_safe_alternative(
    matched: list[dict[str, Any]],
    decision: str,
) -> str | None:
    """Return the safeAlternative of the highest-severity match.

    Falls back to a generic approval hint when at least one
    non-ALLOW rule matched but none provided a specific alternative.
    Returns ``None`` when the final decision is ALLOW.
    """
    if decision == DECISION_ALLOW:
        return None
    sorted_by_severity = sorted(
        matched,
        key=lambda m: (
            DECISION_RANK.get(m["decision"], 0),
            RISK_RANK.get(m["riskLevel"], 0),
        ),
        reverse=True,
    )
    for m in sorted_by_severity:
        alt = m.get("safeAlternative")
        if alt:
            return str(alt)
    return _GENERIC_APPROVAL_HINT


def _build_reason(decision: str, matched: list[dict[str, Any]]) -> str:
    """Produce a one-line explanation for ``decision``."""
    if decision == DECISION_BLOCK:
        ids = sorted({m["ruleId"] for m in matched if m["decision"] == DECISION_BLOCK})
        return f"BLOCKed by {len(ids)} rule(s): {', '.join(ids)}"
    if decision == DECISION_REQUIRE_APPROVAL:
        ids = sorted(
            {m["ruleId"] for m in matched if m["decision"] == DECISION_REQUIRE_APPROVAL}
        )
        return f"Requires human approval by {len(ids)} rule(s): {', '.join(ids)}"
    ids = sorted({m["ruleId"] for m in matched if m["decision"] == DECISION_ALLOW})
    return f"ALLOWed by {len(ids)} rule(s): {', '.join(ids)}"


def _stringify_action(action: Any) -> str:
    """Best-effort conversion of a structured action into a shell-like token.

    The validator can then apply the same regex catalogue without
    inventing a parallel rule format for actions. Unknown action types
    collapse to the bare ``type`` token so the caller still has a
    chance to see them in matchedRules.
    """
    if not isinstance(action, dict):
        return ""

    cmd = action.get("command")
    if isinstance(cmd, str) and cmd.strip():
        return cmd.strip()

    action_type = str(action.get("type", "")).lower()
    target = str(
        action.get("target")
        or action.get("service")
        or action.get("unit")
        or action.get("path")
        or action.get("namespace")
        or ""
    )
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    signal = (parameters or {}).get("signal", "9")

    if action_type in ("kill", "process_kill"):
        return f"kill -{signal} {target}".strip()
    if action_type in ("systemctl_restart", "service_restart"):
        return f"systemctl restart {target}".strip()
    if action_type in ("systemctl_stop", "service_stop"):
        return f"systemctl stop {target}".strip()
    if action_type in ("systemctl_start", "service_start"):
        return f"systemctl start {target}".strip()
    if action_type in ("systemctl_disable", "service_disable"):
        return f"systemctl disable {target}".strip()
    if action_type in ("shutdown",):
        return "shutdown -h now"
    if action_type in ("reboot",):
        return "reboot"
    if action_type in ("delete_file", "rm"):
        return f"rm -rf {target}".strip()
    if action_type in ("chmod",):
        mode = (parameters or {}).get("mode", "")
        return f"chmod {mode} {target}".strip()
    if action_type in ("chown",):
        owner = (parameters or {}).get("owner", "")
        return f"chown {owner} {target}".strip()
    if action_type in ("iptables_flush",):
        return "iptables -F"
    if action_type in ("kubectl_delete_namespace",):
        return f"kubectl delete namespace {target}".strip()
    if action_type in ("kubectl_delete_all_pods",):
        return "kubectl delete pods --all"

    return action_type or ""


__all__ = [
    "IntentValidator",
    "validate_intent",
]
