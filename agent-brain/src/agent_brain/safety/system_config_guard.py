"""Deterministic guardrail that refuses to write critical system config files.

This guard sits *parallel* to ``IntentValidator``. Its job is intentionally
narrow and complementary:

* The intent validator is a *command-pattern* engine (``rm -rf /`` etc).
* This guard is a *path* engine: regardless of how the command looks, if
  any candidate command would *write* to a protected configuration path
  (``/etc/passwd``, ``/etc/shadow``, ``/etc/sudoers``, ``/etc/ssh/sshd_config``,
  ``/etc/systemd/system/*``, ``/boot/*``, ``/lib/modules/*``, ...) we
  return a ``BLOCK`` envelope so the orchestrator can short-circuit
  before any MCP / executor work.

Design notes
------------
* Pure-Python; no I/O. Safe to import from any module.
* Returns a stable envelope shape ``ConfigGuardEnvelope`` so the
  frontend can render a dedicated "configuration protection" card
  even when the decision is ``ALLOW``.
* The guard never *reads* a file - it only matches command text. We
  deliberately stay regex-based because shell-level command parsing
  is undecidable in general, and over-blocking is the safer default.
* Sudo prefixes / leading newlines / heredoc escapes are normalized
  away so attackers cannot wrap a write in ``sudo -E env ...``.
* The instruction text itself is also matched so natural-language
  intent ("please overwrite /etc/passwd with my new content") is
  caught even before a candidate command is synthesized.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"

# Mutually-exclusive risk levels exposed by the guard. Kept identical
# in spirit to ``intent_rules.RISK_*`` so the frontend can reuse the
# same palette.
RISK_LOW = "LOW"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Protected path catalogue
# ---------------------------------------------------------------------------
#
# Each entry is (path_regex, friendly_path_label, severity). The regex
# must match a path *token* in the command text. We anchor on
# whitespace / quoting / redirection on both sides so we don't match
# substrings like ``/etc/passwd-friend`` inside an unrelated argument.

_PathRule = tuple[re.Pattern[str], str, str]


def _path_re(body: str) -> re.Pattern[str]:
    """Compile a path regex with anchoring on shell-token boundaries."""
    return re.compile(
        rf"(?<![A-Za-z0-9_./-]){body}(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )


_PROTECTED_PATHS: tuple[_PathRule, ...] = (
    (_path_re(r"/etc/passwd"), "/etc/passwd", RISK_CRITICAL),
    (_path_re(r"/etc/shadow"), "/etc/shadow", RISK_CRITICAL),
    (_path_re(r"/etc/gshadow"), "/etc/gshadow", RISK_CRITICAL),
    (_path_re(r"/etc/group"), "/etc/group", RISK_HIGH),
    (_path_re(r"/etc/sudoers(?:\.d/[A-Za-z0-9_.\-]+)?"), "/etc/sudoers*", RISK_CRITICAL),
    (_path_re(r"/etc/ssh/sshd_config(?:\.d/[A-Za-z0-9_.\-]+)?"), "/etc/ssh/sshd_config*", RISK_CRITICAL),
    (_path_re(r"/etc/systemd/system/[A-Za-z0-9_.@\-]+"), "/etc/systemd/system/*", RISK_HIGH),
    (_path_re(r"/etc/cron\.(?:d|daily|hourly|monthly|weekly)(?:/[A-Za-z0-9_.\-]+)?"), "/etc/cron.*", RISK_HIGH),
    (_path_re(r"/etc/crontab"), "/etc/crontab", RISK_HIGH),
    (_path_re(r"/etc/hosts"), "/etc/hosts", RISK_HIGH),
    (_path_re(r"/etc/profile(?:\.d/[A-Za-z0-9_.\-]+)?"), "/etc/profile*", RISK_HIGH),
    (_path_re(r"/etc/pam\.d/[A-Za-z0-9_.\-]+"), "/etc/pam.d/*", RISK_CRITICAL),
    (_path_re(r"/etc/security/[A-Za-z0-9_.\-]+"), "/etc/security/*", RISK_HIGH),
    (_path_re(r"/etc/fstab"), "/etc/fstab", RISK_CRITICAL),
    (_path_re(r"/etc/resolv\.conf"), "/etc/resolv.conf", RISK_HIGH),
    (_path_re(r"/etc/login\.defs"), "/etc/login.defs", RISK_HIGH),
    (_path_re(r"/boot/[A-Za-z0-9_.\-/]+"), "/boot/*", RISK_CRITICAL),
    (_path_re(r"/lib/modules/[A-Za-z0-9_.\-/]+"), "/lib/modules/*", RISK_CRITICAL),
    (_path_re(r"/etc/kylin-release"), "/etc/kylin-release", RISK_HIGH),
    (_path_re(r"/etc/os-release"), "/etc/os-release", RISK_HIGH),
)


# ---------------------------------------------------------------------------
# Write verbs
# ---------------------------------------------------------------------------
#
# We match common write/mutate utilities. Combined with a protected
# path token, the guard returns BLOCK. Output-redirection operators are
# treated separately because they may follow ANY command.

# Verbs are anchored with ``(?<![/.])`` so a path component like
# ``/etc/passwd`` cannot satisfy the ``passwd`` verb. Each pattern is
# case-insensitive and matches the canonical command name only.

def _verb(body: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![/.\w])(?:{body})(?![A-Za-z0-9_-])", re.IGNORECASE)


_WRITE_VERBS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_verb(r"tee"), "tee"),
    (_verb(r"dd"), "dd"),
    (_verb(r"cp"), "cp"),
    (_verb(r"mv"), "mv"),
    (_verb(r"install"), "install"),
    (re.compile(r"(?<![/.\w])sed\b[^|;&]*-i", re.IGNORECASE), "sed -i"),
    (_verb(r"rm"), "rm"),
    (_verb(r"chmod"), "chmod"),
    (_verb(r"chown"), "chown"),
    (_verb(r"chattr"), "chattr"),
    (_verb(r"truncate"), "truncate"),
    (re.compile(r"(?<![/.\w])ln\s+-s?f\b", re.IGNORECASE), "ln -sf"),
    (_verb(r"visudo"), "visudo"),
    (_verb(r"vi(?:m)?"), "vim"),
    (_verb(r"nano"), "nano"),
    (_verb(r"passwd"), "passwd"),
    (_verb(r"chpasswd"), "chpasswd"),
    (_verb(r"useradd"), "useradd"),
    (_verb(r"usermod"), "usermod"),
    (_verb(r"groupadd"), "groupadd"),
)

# Shell redirection that turns ANY command into a write to the target.
_REDIRECT_RE = re.compile(r">{1,2}")


# Natural-language hints in the instruction that imply a write intent.
# Matching these alone is NOT enough to BLOCK; we still require a
# protected path token in the instruction or candidate commands.
_NL_WRITE_HINTS = re.compile(
    r"(?:覆盖|写入|改写|清空|追加|追写|修改|篡改|编辑|删除|"
    r"overwrite|append|modify|edit|tamper|wipe|truncate|rewrite)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchedPath:
    """One protected-path hit inside a command or instruction."""

    label: str
    risk: str
    matchedIn: str  # "command" | "instruction"
    snippet: str


@dataclass(frozen=True)
class ConfigGuardEnvelope:
    """Stable response envelope returned by :func:`evaluate`."""

    decision: str
    riskLevel: str
    matchedPaths: list[MatchedPath] = field(default_factory=list)
    matchedVerb: str | None = None
    reason: str = ""
    reasonZh: str = ""

    def to_dict(self) -> dict[str, object]:
        """Plain-dict representation for JSON serialization / audit log."""
        return {
            "decision": self.decision,
            "riskLevel": self.riskLevel,
            "matchedPaths": [
                {
                    "label": m.label,
                    "risk": m.risk,
                    "matchedIn": m.matchedIn,
                    "snippet": m.snippet,
                }
                for m in self.matchedPaths
            ],
            "matchedVerb": self.matchedVerb,
            "reason": self.reason,
            "reasonZh": self.reasonZh,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SUDO_PREFIX_RE = re.compile(r"^\s*sudo(?:\s+-[A-Za-z]+)*\s+", re.IGNORECASE)
_SNIPPET_LIMIT = 200


def _strip_sudo(cmd: str) -> str:
    """Drop a leading ``sudo`` (and option flags) so verbs match cleanly."""
    return _SUDO_PREFIX_RE.sub("", cmd or "", count=1)


def _truncate(text: str) -> str:
    """Bound snippet length so it stays UI-displayable."""
    if len(text) <= _SNIPPET_LIMIT:
        return text
    return text[: _SNIPPET_LIMIT - 3] + "..."


def _scan_text_for_paths(text: str, *, matched_in: str) -> list[MatchedPath]:
    """Return every protected-path hit inside ``text``."""
    out: list[MatchedPath] = []
    if not text:
        return out
    for pattern, label, risk in _PROTECTED_PATHS:
        if pattern.search(text):
            out.append(
                MatchedPath(
                    label=label,
                    risk=risk,
                    matchedIn=matched_in,
                    snippet=_truncate(text),
                )
            )
    return out


def _find_write_verb(cmd: str) -> str | None:
    """Return the matched write verb for the given command, or None."""
    if not cmd:
        return None
    if _REDIRECT_RE.search(cmd):
        return ">>"
    body = _strip_sudo(cmd)
    for pattern, label in _WRITE_VERBS:
        if pattern.search(body):
            return label
    return None


def _max_risk(matches: Iterable[MatchedPath]) -> str:
    """Reduce a list of path matches to the highest risk level."""
    rank = {RISK_LOW: 0, RISK_HIGH: 1, RISK_CRITICAL: 2}
    best = RISK_LOW
    for m in matches:
        if rank.get(m.risk, 0) > rank.get(best, 0):
            best = m.risk
    return best


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate(
    *,
    instruction: str = "",
    candidate_commands: list[str] | None = None,
) -> ConfigGuardEnvelope:
    """Decide whether the request would write to a protected config file.

    Returns a :class:`ConfigGuardEnvelope` with ``decision`` set to
    ``BLOCK`` if any candidate command (or, with a write hint, the
    instruction text) touches a protected path. Otherwise ``ALLOW``.
    """
    commands = [str(c or "").strip() for c in (candidate_commands or []) if str(c or "").strip()]
    instruction_text = (instruction or "").strip()

    cmd_matches: list[MatchedPath] = []
    verb: str | None = None
    for cmd in commands:
        path_hits = _scan_text_for_paths(cmd, matched_in="command")
        if not path_hits:
            continue
        cmd_verb = _find_write_verb(cmd)
        if cmd_verb is None:
            continue
        verb = verb or cmd_verb
        cmd_matches.extend(path_hits)

    instruction_matches: list[MatchedPath] = []
    if not cmd_matches and instruction_text:
        # Two ways an instruction alone can trigger BLOCK:
        #   1. natural-language write hint + protected path
        #      ("请覆盖 /etc/passwd")
        #   2. raw shell-style write verb + protected path
        #      ("echo x | sudo tee -a /etc/passwd")
        # We always check (2) first because it is more specific and
        # captures the verb for the audit envelope; (1) is a fallback
        # for free-form natural language.
        ins_verb = _find_write_verb(instruction_text)
        if ins_verb is not None:
            ins_hits = _scan_text_for_paths(instruction_text, matched_in="instruction")
            if ins_hits:
                verb = verb or ins_verb
                instruction_matches = ins_hits
        if not instruction_matches and _NL_WRITE_HINTS.search(instruction_text):
            instruction_matches = _scan_text_for_paths(
                instruction_text, matched_in="instruction"
            )

    all_matches = cmd_matches + instruction_matches
    if not all_matches:
        return ConfigGuardEnvelope(
            decision=DECISION_ALLOW,
            riskLevel=RISK_LOW,
            matchedPaths=[],
            matchedVerb=None,
            reason="No protected configuration path touched by this request.",
            reasonZh="本次请求未触及关键系统配置文件，确定性护栏放行。",
        )

    risk_level = _max_risk(all_matches)
    path_labels = sorted({m.label for m in all_matches})
    label_csv = ", ".join(path_labels)
    return ConfigGuardEnvelope(
        decision=DECISION_BLOCK,
        riskLevel=risk_level,
        matchedPaths=all_matches,
        matchedVerb=verb,
        reason=(
            f"Configuration guard BLOCKED: write attempt to protected path(s) "
            f"[{label_csv}]"
            + (f" via '{verb}'" if verb else "")
            + "."
        ),
        reasonZh=(
            f"确定性护栏拦截：检测到对受保护配置路径 [{label_csv}] 的写入意图"
            + (f"（使用 {verb}）" if verb else "")
            + "，按策略一律拒绝执行。"
        ),
    )


__all__ = [
    "DECISION_ALLOW",
    "DECISION_BLOCK",
    "RISK_LOW",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "ConfigGuardEnvelope",
    "MatchedPath",
    "evaluate",
]
