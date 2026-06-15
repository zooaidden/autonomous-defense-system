"""Lightweight prompt-injection / jailbreak detector for the OPS agent.

This module is intentionally *rule-based*: the OPS Agent does not own
the LLM session, so we cannot rely on the model to defend itself. We
front-load a fast, deterministic pre-check that:

* rejects classic jailbreak prefixes ("ignore previous instructions",
  "you are now in developer mode", "请忽略上面的指令", ...);
* rejects role-hijack templates that try to forge a fake system turn
  (``<|im_start|>system``, ``[INST]``, ``### system``, ...);
* rejects long base64 / heavily URL-encoded payloads that smell like
  smuggled commands;
* rejects natural-language inputs that immediately chain a command
  separator (``do X; rm -rf /``);
* rejects abnormally long inputs that look like a paste-bombing
  attempt to exhaust context.

The guard returns an :class:`InjectionEnvelope` so the orchestrator
and the frontend can render a dedicated "prompt-injection protection"
card even when the decision is ``ALLOW``.

Pure-Python; no I/O. Safe to import from any module.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _InjectionRule:
    """One injection-detection regex paired with metadata."""

    rule_id: str
    risk: str
    description: str
    pattern: re.Pattern[str]


def _ci(pat: str) -> re.Pattern[str]:
    """Helper: case-insensitive, multiline-ish compile."""
    return re.compile(pat, re.IGNORECASE | re.DOTALL)


_RULES: tuple[_InjectionRule, ...] = (
    # ---- Role hijack / instruction override (English) -------------------
    _InjectionRule(
        rule_id="PI-001",
        risk=RISK_HIGH,
        description="English instruction override ('ignore previous/above instructions').",
        pattern=_ci(r"\bignore\s+(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|messages?)"),
    ),
    _InjectionRule(
        rule_id="PI-002",
        risk=RISK_HIGH,
        description="English persona switch / developer-mode jailbreak.",
        pattern=_ci(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|debug|jailbreak|admin|root|sudo)\b|\bdeveloper\s+mode\b|\bdan\s+mode\b|\bdo\s+anything\s+now\b"),
    ),
    _InjectionRule(
        rule_id="PI-003",
        risk=RISK_HIGH,
        description="English request to disclose system prompt or rules.",
        pattern=_ci(r"\b(?:print|reveal|show|leak|dump)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions?|secret\s+rules?)\b"),
    ),
    # ---- Role hijack / instruction override (Chinese) -------------------
    _InjectionRule(
        rule_id="PI-010",
        risk=RISK_HIGH,
        description="Chinese instruction override ('请忽略上面的指令').",
        pattern=_ci(r"忽略(?:[^。\n]{0,8})?(?:以上|上面|前面|前文|之前)(?:[^。\n]{0,8})?(?:指令|提示|提示词|规则|系统|消息)"),
    ),
    _InjectionRule(
        rule_id="PI-011",
        risk=RISK_HIGH,
        description="Chinese persona switch ('扮演 root / 管理员 / 黑客').",
        pattern=_ci(r"(?:扮演|装作|假装|现在你是)\s*(?:管理员|超级用户|root|黑客|hacker|超级管理员|开发者模式|越狱模式)"),
    ),
    _InjectionRule(
        rule_id="PI-012",
        risk=RISK_HIGH,
        description="Chinese demand to disclose system prompt.",
        pattern=_ci(r"(?:输出|展示|公开|透露|告诉我).{0,4}(?:系统提示|隐藏指令|内部规则|预设规则|底层提示)"),
    ),
    # ---- Template / chat-turn hijack ------------------------------------
    _InjectionRule(
        rule_id="PI-020",
        risk=RISK_CRITICAL,
        description="ChatML / template marker injected by user input.",
        pattern=re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"),
    ),
    _InjectionRule(
        rule_id="PI-021",
        risk=RISK_HIGH,
        description="Llama / instruction template marker.",
        pattern=re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"),
    ),
    _InjectionRule(
        rule_id="PI-022",
        risk=RISK_HIGH,
        description="Markdown system header used to forge a system turn.",
        pattern=_ci(r"^\s*#{1,6}\s*system\b", ),
    ),
    _InjectionRule(
        rule_id="PI-023",
        risk=RISK_MEDIUM,
        description="HTML/script tag injection inside user text.",
        pattern=_ci(r"</?(?:script|iframe|object|embed)\b"),
    ),
    # ---- Encoded payloads ----------------------------------------------
    _InjectionRule(
        rule_id="PI-030",
        risk=RISK_MEDIUM,
        description="Long base64-like blob (>= 80 chars) that looks like a smuggled payload.",
        pattern=re.compile(r"(?:[A-Za-z0-9+/]{80,}={0,2})"),
    ),
    # ---- Command injection inside natural language ---------------------
    _InjectionRule(
        rule_id="PI-040",
        risk=RISK_HIGH,
        description="Natural-language input ends with a shell-style command chain.",
        pattern=_ci(r"[;&|]{1,2}\s*(?:rm|chmod|chown|mkfs|dd|curl|wget|bash|sh|nc|ncat)\b"),
    ),
)


# Threshold for the long-input rule. Larger than expected operator
# inputs but well below typical LLM context limits, so any normal user
# request is well under.
_MAX_INPUT_CHARS = 4000

# Threshold for the URL-encoded-density rule.
_URL_ENC_DENSITY = 0.30


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchedInjection:
    """One injection-rule hit inside the inspected text."""

    ruleId: str
    risk: str
    description: str
    sample: str


@dataclass(frozen=True)
class InjectionEnvelope:
    """Stable response envelope returned by :func:`inspect`."""

    decision: str
    riskLevel: str
    matchedPatterns: list[MatchedInjection] = field(default_factory=list)
    reason: str = ""
    reasonZh: str = ""

    def to_dict(self) -> dict[str, object]:
        """Plain-dict representation for JSON serialization."""
        return {
            "decision": self.decision,
            "riskLevel": self.riskLevel,
            "matchedPatterns": [
                {
                    "ruleId": m.ruleId,
                    "risk": m.risk,
                    "description": m.description,
                    "sample": m.sample,
                }
                for m in self.matchedPatterns
            ],
            "reason": self.reason,
            "reasonZh": self.reasonZh,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SAMPLE_LIMIT = 80
_URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _sample(text: str, match: re.Match[str]) -> str:
    """Return a short, UI-safe slice around the match position."""
    start = max(0, match.start() - 20)
    end = min(len(text), match.end() + 20)
    fragment = text[start:end]
    if len(fragment) > _SAMPLE_LIMIT:
        fragment = fragment[: _SAMPLE_LIMIT - 3] + "..."
    return fragment.replace("\n", " ").replace("\r", " ").strip()


def _url_encoded_density(text: str) -> float:
    """Fraction of characters that look URL-encoded (``%xx``)."""
    if not text:
        return 0.0
    encoded = sum(3 for _ in _URL_ENC_RE.finditer(text))
    return encoded / max(1, len(text))


def _max_risk(matches: Iterable[MatchedInjection]) -> str:
    """Reduce a list of matches to the highest risk level seen."""
    rank = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2, RISK_CRITICAL: 3}
    best = RISK_LOW
    for m in matches:
        if rank.get(m.risk, 0) > rank.get(best, 0):
            best = m.risk
    return best


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def inspect(instruction: str | None) -> InjectionEnvelope:
    """Run all injection rules against the user-supplied instruction.

    Returns a :class:`InjectionEnvelope` with ``decision`` set to
    ``BLOCK`` if any rule fires, otherwise ``ALLOW``. The envelope
    always lists the matched rules so the frontend can show *why* a
    request was refused.
    """
    text = instruction or ""

    matches: list[MatchedInjection] = []

    if len(text) > _MAX_INPUT_CHARS:
        matches.append(
            MatchedInjection(
                ruleId="PI-050",
                risk=RISK_MEDIUM,
                description=f"Instruction exceeds {_MAX_INPUT_CHARS} chars (paste-bomb).",
                sample=f"len={len(text)}",
            )
        )

    density = _url_encoded_density(text)
    if density >= _URL_ENC_DENSITY and len(text) >= 60:
        matches.append(
            MatchedInjection(
                ruleId="PI-051",
                risk=RISK_MEDIUM,
                description=f"URL-encoded payload density {density:.0%} >= 30%.",
                sample=text[:_SAMPLE_LIMIT],
            )
        )

    for rule in _RULES:
        match = rule.pattern.search(text)
        if match is None:
            continue
        matches.append(
            MatchedInjection(
                ruleId=rule.rule_id,
                risk=rule.risk,
                description=rule.description,
                sample=_sample(text, match),
            )
        )

    if not matches:
        return InjectionEnvelope(
            decision=DECISION_ALLOW,
            riskLevel=RISK_LOW,
            matchedPatterns=[],
            reason="No prompt-injection pattern detected.",
            reasonZh="未检测到提示词注入特征，反注入护栏放行。",
        )

    risk_level = _max_risk(matches)
    rule_ids = sorted({m.ruleId for m in matches})
    return InjectionEnvelope(
        decision=DECISION_BLOCK,
        riskLevel=risk_level,
        matchedPatterns=matches,
        reason=(
            f"Prompt injection BLOCKED: matched {len(rule_ids)} rule(s) "
            f"[{', '.join(rule_ids)}]."
        ),
        reasonZh=(
            f"反注入护栏拦截：命中 {len(rule_ids)} 条注入规则 "
            f"[{', '.join(rule_ids)}]，已拒绝该指令进入下游推理。"
        ),
    )


__all__ = [
    "DECISION_ALLOW",
    "DECISION_BLOCK",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "InjectionEnvelope",
    "MatchedInjection",
    "inspect",
]
