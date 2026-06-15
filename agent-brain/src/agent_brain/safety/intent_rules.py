"""Static rule catalogue for the OPS intent validator.

This module is intentionally data-only: every rule is a frozen
:class:`IntentRule` and the regex patterns are compiled at import time
(once per process). Keeping rules in Python (rather than JSON) makes
security review easy, takes advantage of raw-string regex literals, and
lets reviewers grep ``rule_id`` strings to find the originating
catalogue entry.

Each rule carries:

    rule_id          stable identifier ("B-001", "R-001", "A-001", ...)
    decision         "ALLOW" / "REQUIRE_APPROVAL" / "BLOCK"
    risk_level       "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
    pattern          compiled regex (case-insensitive)
    description      one-line reason emitted in matchedRules
    safe_alternative optional safer command suggestion (or None)

Decision precedence (used by the validator to reduce a list of matches
into a single answer): ``BLOCK > REQUIRE_APPROVAL > ALLOW``. Risk level
precedence: ``CRITICAL > HIGH > MEDIUM > LOW``. Both are exposed as
``DECISION_RANK`` / ``RISK_RANK`` maps so downstream sorters can reuse
them without duplicating the constants.

The catalogue is intentionally over-specified for the dangerous cases
(several narrow patterns rather than one giant regex) so a single
audit-time edit can disable / strengthen one specific scenario without
touching unrelated rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Decision and risk constants
# ---------------------------------------------------------------------------

DECISION_ALLOW = "ALLOW"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
DECISION_BLOCK = "BLOCK"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

# ---------------------------------------------------------------------------
# Danger category constants (used by danger_catalogue.py)
# ---------------------------------------------------------------------------

DANGER_DESTRUCTIVE_ROOT = "destructive_root"
DANGER_PERMISSION_777 = "permission_777"
DANGER_PERMISSION_CHOWN_ROOT = "permission_chown_root"
DANGER_FS_FORMAT = "filesystem_format"
DANGER_DISK_OVERWRITE = "disk_overwrite"
DANGER_HOST_OFFLINE = "host_offline"
DANGER_REMOTE_SCRIPT_EXEC = "remote_script_exec"
DANGER_FORK_BOMB = "fork_bomb"
DANGER_FIREWALL_FLUSH = "firewall_flush"
DANGER_FIREWALL_PERMANENT_REMOVE = "firewall_permanent_remove"
DANGER_K8S_DELETE_NS = "k8s_delete_namespace"
DANGER_K8S_DELETE_ALL = "k8s_delete_all"
DANGER_LOG_DESTRUCTION = "log_destruction"
DANGER_KYLINSEC_DISABLE = "kylinsec_disable"
DANGER_TCM_TAMPER = "tcm_tamper"
DANGER_BOOT_CHAIN_BREAK = "boot_chain_break"
DANGER_REPO_TAMPER = "repo_tamper"
DANGER_UNSIGNED_MODULE = "unsigned_module"
DANGER_IMA_POLICY_TAMPER = "ima_policy_tamper"
DANGER_AUDIT_DISABLE = "audit_disable"
DANGER_FIRMWARE_WRITE = "firmware_write"

# Precedence for the danger catalogue display.
DANGER_CATEGORY_LABELS: dict[str, str] = {
    DANGER_DESTRUCTIVE_ROOT: "删除根目录文件",
    DANGER_PERMISSION_777: "系统目录权限设为777",
    DANGER_PERMISSION_CHOWN_ROOT: "系统目录所有者改为root",
    DANGER_FS_FORMAT: "格式化磁盘",
    DANGER_DISK_OVERWRITE: "直接写入块设备",
    DANGER_HOST_OFFLINE: "关闭/重启主机",
    DANGER_REMOTE_SCRIPT_EXEC: "远程脚本管道执行",
    DANGER_FORK_BOMB: "Fork炸弹",
    DANGER_FIREWALL_FLUSH: "清空防火墙规则",
    DANGER_FIREWALL_PERMANENT_REMOVE: "永久移除防火墙规则",
    DANGER_K8S_DELETE_NS: "删除K8s命名空间",
    DANGER_K8S_DELETE_ALL: "批量删除K8s资源",
    DANGER_LOG_DESTRUCTION: "删除系统日志",
    DANGER_KYLINSEC_DISABLE: "禁用麒麟安全框架",
    DANGER_TCM_TAMPER: "篡改TCM可信模块",
    DANGER_BOOT_CHAIN_BREAK: "破坏可信启动链",
    DANGER_REPO_TAMPER: "篡改麒麟软件源",
    DANGER_UNSIGNED_MODULE: "强制加载未签名内核模块",
    DANGER_IMA_POLICY_TAMPER: "篡改IMA完整性策略",
    DANGER_AUDIT_DISABLE: "禁用内核审计子系统",
    DANGER_FIRMWARE_WRITE: "写入LoongArch固件",
}

# Higher value -> takes priority when collapsing multiple matches.
DECISION_RANK: dict[str, int] = {
    DECISION_ALLOW: 0,
    DECISION_REQUIRE_APPROVAL: 1,
    DECISION_BLOCK: 2,
}

RISK_RANK: dict[str, int] = {
    RISK_LOW: 1,
    RISK_MEDIUM: 2,
    RISK_HIGH: 3,
    RISK_CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntentRule:
    """A single safety rule.

    ``frozen=True`` ensures rule entries are immutable post-construction
    so subtle in-place tweaks at runtime are impossible.
    """

    rule_id: str
    decision: str
    risk_level: str
    pattern: re.Pattern[str]
    description: str
    safe_alternative: str | None = None
    danger_category: str | None = None


# ---------------------------------------------------------------------------
# Helper: compile a case-insensitive regex once at import time.
# ---------------------------------------------------------------------------


def _re(pattern: str) -> re.Pattern[str]:
    """Compile ``pattern`` with case-insensitive flag."""
    return re.compile(pattern, re.IGNORECASE)


# Top-level system directories whose recursive deletion / chmod / chown
# is always a BLOCK regardless of who issues it. Kept as a constant so
# reviewers can audit the list in one place. Sub-paths under these
# directories fall back to REQUIRE_APPROVAL via the generic R-rules.
_TOP_LEVEL_SYS_DIRS = "etc|usr|var|home|opt|root|bin|sbin|lib|lib64|boot|sys|proc|dev"


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

RULES: tuple[IntentRule, ...] = (
    # =========================================================================
    # BLOCK rules
    # =========================================================================

    # B-001: rm -rf /  /  rm -rf /*  /  rm -rf / --no-preserve-root
    IntentRule(
        rule_id="B-001",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|"
            r"-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|"
            r"--recursive\s+--force|--force\s+--recursive)"
            r"\s+/(?:\s|$|\*)"
        ),
        description="Recursive force-delete of the root filesystem ('rm -rf /' or '/*')",
        safe_alternative=(
            "Restrict rm -rf to a specific application subdirectory; "
            "never target the root filesystem"
        ),
        danger_category=DANGER_DESTRUCTIVE_ROOT,
    ),

    # B-001b: explicit override of rm root protection
    IntentRule(
        rule_id="B-001b",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\brm\b[^|;&]*--no-preserve-root\b"),
        description="Explicit override of rm's root-preservation safety",
        safe_alternative="Drop --no-preserve-root; the flag should never be required for ops",
        danger_category=DANGER_DESTRUCTIVE_ROOT,
    ),

    # B-001c: rm -rf <top-level system dir>
    IntentRule(
        rule_id="B-001c",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|"
            r"-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)"
            rf"\s+/(?:{_TOP_LEVEL_SYS_DIRS})(?:/\*)?(?:\s|;|$)"
        ),
        description="Recursive force-delete of a top-level system directory",
        safe_alternative=(
            "Limit deletion to a specific application subdirectory below the system path"
        ),
        danger_category=DANGER_DESTRUCTIVE_ROOT,
    ),

    # B-002: chmod 777 on root or top-level system dir (recursive variants too)
    IntentRule(
        rule_id="B-002",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bchmod\s+(?:-R\s+)?777\s+(?:-R\s+)?"
            rf"(?:/(?:\s|$|\*)|/(?:{_TOP_LEVEL_SYS_DIRS})(?:/\*)?(?:\s|;|$))"
        ),
        description="World-writable (777) permissions on root or top-level system path",
        safe_alternative="Set the minimum required permissions on a specific file or directory",
        danger_category=DANGER_PERMISSION_777,
    ),

    # B-002b: chmod -R 777 / (any "recursive 777 from root")
    IntentRule(
        rule_id="B-002b",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\bchmod\s+-R\s+777\s+/"),
        description="Recursive 777 permissions starting at the root filesystem",
        safe_alternative="Avoid recursive 777; assign least-privilege perms per file",
        danger_category=DANGER_PERMISSION_777,
    ),

    # B-003: chown -R root <root or system dir>
    IntentRule(
        rule_id="B-003",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bchown\s+(?:-R\s+)?(?:[A-Za-z0-9_.\-]+:)?root"
            r"(?::[A-Za-z0-9_.\-]+)?\s+(?:-R\s+)?"
            rf"(?:/(?:\s|$|\*)|/(?:{_TOP_LEVEL_SYS_DIRS})(?:/\*)?(?:\s|;|$))"
        ),
        description="Recursive chown to root on root or a top-level system path",
        safe_alternative=(
            "Restrict chown to a specific subdirectory and to the application's runtime user"
        ),
        danger_category=DANGER_PERMISSION_CHOWN_ROOT,
    ),

    # B-004: mkfs (any filesystem creation)
    IntentRule(
        rule_id="B-004",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\bmkfs(?:\.[a-z0-9]+)?\b"),
        description="Filesystem (re)creation destroys all data on the target device",
        safe_alternative=(
            "Use lsblk/blkid to inspect; never run mkfs without an explicit human approval"
        ),
        danger_category=DANGER_FS_FORMAT,
    ),

    # B-005: dd writing to /dev/<device>
    IntentRule(
        rule_id="B-005",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\bdd\b[^|;&]*\bof=/dev/[a-z0-9]+"),
        description="dd writing directly to a block device is irreversible",
        safe_alternative=(
            "Avoid writing to /dev/*; use file-based output or a dedicated partitioning tool"
        ),
        danger_category=DANGER_DISK_OVERWRITE,
    ),

    # B-006: shutdown / reboot / halt / poweroff / init 0|6
    IntentRule(
        rule_id="B-006",
        decision=DECISION_BLOCK,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b"
        ),
        description="System shutdown / reboot - takes the host offline",
        safe_alternative=(
            "Restart specific services with 'systemctl restart <unit>'; "
            "coordinate full reboots with operators"
        ),
        danger_category=DANGER_HOST_OFFLINE,
    ),

    # B-007: pipe-to-shell of remote content (curl|sh, wget|bash, ...)
    IntentRule(
        rule_id="B-007",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*"
            r"(?:sh|bash|zsh|ksh|fish|dash)\b"
        ),
        description="Piping remote content directly into a shell - arbitrary code execution",
        safe_alternative="Download to a file, inspect/checksum, then run the script explicitly",
        danger_category=DANGER_REMOTE_SCRIPT_EXEC,
    ),

    # B-008: classic bash fork bomb (whitespace-tolerant)
    IntentRule(
        rule_id="B-008",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        description="Bash fork bomb - exhausts the process table",
        safe_alternative=None,
        danger_category=DANGER_FORK_BOMB,
    ),

    # B-009: iptables -F / iptables --flush
    IntentRule(
        rule_id="B-009",
        decision=DECISION_BLOCK,
        risk_level=RISK_HIGH,
        pattern=_re(r"\biptables\s+(?:-[A-Za-z]*F[A-Za-z]*|--flush)\b"),
        description="Flushing iptables clears every firewall rule",
        safe_alternative="Modify a specific rule; run 'iptables -L -n' first to inspect",
        danger_category=DANGER_FIREWALL_FLUSH,
    ),

    # B-010: firewall-cmd --permanent --remove*
    IntentRule(
        rule_id="B-010",
        decision=DECISION_BLOCK,
        risk_level=RISK_HIGH,
        pattern=_re(r"\bfirewall-cmd\b[^|;&]*--permanent\b[^|;&]*--remove"),
        description="Permanent removal of firewalld rules",
        safe_alternative=(
            "Test the change with --runtime first; remove only the specific rule by identifier"
        ),
        danger_category=DANGER_FIREWALL_PERMANENT_REMOVE,
    ),

    # B-011: kubectl delete namespace
    IntentRule(
        rule_id="B-011",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\bkubectl\s+delete\s+(?:ns|namespace|namespaces)\b"),
        description="Deleting a Kubernetes namespace destroys every resource within",
        safe_alternative="Delete specific resources individually with a documented migration plan",
        danger_category=DANGER_K8S_DELETE_NS,
    ),

    # B-012: kubectl delete <resource> --all
    IntentRule(
        rule_id="B-012",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bkubectl\s+delete\s+"
            r"(?:pod|pods|deployment|deployments|svc|service|services|"
            r"ds|daemonset|daemonsets|sts|statefulset|statefulsets|"
            r"job|jobs|cronjob|cronjobs|cm|configmap|configmaps|"
            r"secret|secrets|pvc|pv)\b[^|;&]*--all\b"
        ),
        description="Mass deletion of Kubernetes resources via --all",
        safe_alternative=(
            "Target specific resources by name or label; preview with --dry-run=server first"
        ),
        danger_category=DANGER_K8S_DELETE_ALL,
    ),

    # B-013: rm targeting /var/log subtree (delete system logs)
    IntentRule(
        rule_id="B-013",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(r"\brm\b\s+(?:-[a-zA-Z]+\s+)*/var/log(?:/|\s|$|;)"),
        description="Deleting system logs destroys audit evidence",
        safe_alternative="Rotate logs with logrotate; never rm system log files",
        danger_category=DANGER_LOG_DESTRUCTION,
    ),

    # =========================================================================
    # Kylin / LoongArch BLOCK rules (B-014 – B-021)
    # =========================================================================

    # B-014: kylinsec disable / off / stop
    IntentRule(
        rule_id="B-014",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bkylinsec\s+(?:disable|off|stop|set\s+mode\s+disabled"
            r"|set\s+mode\s+permissive)"
        ),
        description="Disabling KylinSec MAC removes kernel-level mandatory access control",
        safe_alternative=(
            "Run 'kylinsec-status' to inspect the current policy. "
            "Never disable KylinSec via an automated agent."
        ),
        danger_category=DANGER_KYLINSEC_DISABLE,
    ),

    # B-015: TCM PCR tampering
    IntentRule(
        rule_id="B-015",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:tcm(?:ctl|_info|_set)|tcmr)\w*\s+"
            r"(?:reset|clear|wipe|delete)\s+(?:pcr|register|key)"
        ),
        description="Resetting TCM PCR registers destroys remote attestation evidence",
        safe_alternative=(
            "Read PCR values with 'tcm_get_info' or via /sys/class/tcm/tcm0/pcrs. "
            "Never clear or reset TCM registers."
        ),
        danger_category=DANGER_TCM_TAMPER,
    ),

    # B-016: trusted boot chain tampering
    IntentRule(
        rule_id="B-016",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:efibootmgr|grub2?-mkconfig|grub2?-install|efivar)\b"
            r"[^|;&]*\b(?:delete|remove|--force|write|update)"
        ),
        description="Modifying trusted boot chain breaks measured boot integrity",
        safe_alternative=(
            "Boot entries should only be changed during scheduled maintenance "
            "with explicit operator approval. Read current entries with 'efibootmgr -v'."
        ),
        danger_category=DANGER_BOOT_CHAIN_BREAK,
    ),

    # B-017: Kylin repository tampering
    IntentRule(
        rule_id="B-017",
        decision=DECISION_BLOCK,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"\b(?:rm|mv|sed\s+-i|tee|cat\s*>)\b"
            r"[^|;&]*\b/etc/yum\.repos\.d[/A-Za-z0-9_.\-]*kylin"
        ),
        description="Removing or modifying Kylin repository configuration undermines trusted software supply chain",
        safe_alternative=(
            "Use 'dnf repolist' to inspect enabled repositories. "
            "Repository changes must go through configuration management."
        ),
        danger_category=DANGER_REPO_TAMPER,
    ),

    # B-018: modprobe --force (unsigned kernel module)
    IntentRule(
        rule_id="B-018",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:modprobe|insmod)\b[^|;&]*"
            r"(?:--force|--force-unsupported|--allow-unsupported)"
        ),
        description="Force-loading an unsigned or unsupported kernel module bypasses Kylin module signature enforcement",
        safe_alternative=(
            "Only load kernel modules that are signed and packaged by the Kylin "
            "distribution. Verify signatures with 'modinfo <module> | grep sig'."
        ),
        danger_category=DANGER_UNSIGNED_MODULE,
    ),

    # B-019: IMA policy tampering
    IntentRule(
        rule_id="B-019",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"(?:echo|tee|cat|dd)\b[^|;&]*"
            r">>?\s*/sys/kernel/security/ima/policy"
        ),
        description="Modifying IMA (Integrity Measurement Architecture) policy undermines file integrity assurance",
        safe_alternative=(
            "IMA policy is set at boot via kernel command line. "
            "Read the current policy with 'cat /sys/kernel/security/ima/policy'."
        ),
        danger_category=DANGER_IMA_POLICY_TAMPER,
    ),

    # B-020: audit subsystem disable / reset
    IntentRule(
        rule_id="B-020",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bauditctl\s+(?:-e\s+0|--reset|-D)\b"
        ),
        description="Disabling or resetting the kernel audit subsystem destroys forensic evidence",
        safe_alternative=(
            "View current audit rules with 'auditctl -l'. "
            "Audit configuration changes require offline maintenance windows."
        ),
        danger_category=DANGER_AUDIT_DISABLE,
    ),

    # B-021: LoongArch firmware write
    IntentRule(
        rule_id="B-021",
        decision=DECISION_BLOCK,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:flashrom|loongson-efi|efivar|loongarch-flash)\b"
            r"[^|;&]*\b(?:write|update|flash|erase)\b"
        ),
        description="Writing to LoongArch firmware is irreversible and can brick the host",
        safe_alternative=(
            "Firmware updates must be performed via the Kylin vendor-provided "
            "update mechanism during planned maintenance. Never via an automated agent."
        ),
        danger_category=DANGER_FIRMWARE_WRITE,
    ),

    # =========================================================================
    # REQUIRE_APPROVAL rules
    # =========================================================================

    # R-001: kill -9 (force-kill)
    IntentRule(
        rule_id="R-001",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(r"\bkill\s+(?:-9\b|-SIGKILL\b|-s\s+9\b|-s\s+KILL\b)"),
        description="Force-kill (-9) bypasses graceful shutdown handlers",
        safe_alternative="Try 'kill -TERM <pid>' first to allow graceful shutdown",
    ),

    # R-002: systemctl restart <unit>
    IntentRule(
        rule_id="R-002",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(r"\bsystemctl\s+restart\b"),
        description="Restarting a systemd unit briefly interrupts service",
        safe_alternative="Use 'systemctl reload' if the unit supports zero-downtime reload",
    ),

    # R-003: systemctl stop / disable / mask
    IntentRule(
        rule_id="R-003",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(r"\bsystemctl\s+(?:stop|disable|mask)\b"),
        description="Stopping / disabling / masking a systemd unit removes service",
        safe_alternative="Confirm there is no active dependency on the unit before stopping",
    ),

    # R-004: modify sshd_config (any of sed -i, vi, echo>>, tee, cat>, etc.)
    IntentRule(
        rule_id="R-004",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"(?:\b(?:sed\s+-i|tee|cat|echo|nano|vi(?:m)?|emacs|ed)\b[^|;&]*|"
            r">>?\s*)/etc/ssh/sshd_config\b"
        ),
        description="Touching sshd_config can lock you out of the host",
        safe_alternative=(
            "Stage changes via configuration management; "
            "validate with 'sshd -t' before reload"
        ),
    ),

    # R-005: modify firewall rules (iptables/ip6tables/nft/firewall-cmd/ufw)
    IntentRule(
        rule_id="R-005",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"\b(?:iptables|ip6tables|nft|firewall-cmd|ufw)\b\s+"
            r"(?:-[AID]\b|--add\b|--insert\b|--remove\b|"
            r"add\b|delete\b|insert\b|allow\b|deny\b|reject\b|drop\b)"
        ),
        description="Adding / removing firewall rules can break connectivity",
        safe_alternative=(
            "Snapshot current rules before changing; verify reachability after"
        ),
    ),

    # R-006: chmod -R (recursive permission change, any target)
    IntentRule(
        rule_id="R-006",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_MEDIUM,
        pattern=_re(r"\bchmod\s+-R\b"),
        description="Recursive permission change can over-grant access",
        safe_alternative=(
            "Restrict chmod -R to a specific application directory; prefer per-file chmod"
        ),
    ),

    # R-007: chown -R (recursive ownership change, any target)
    IntentRule(
        rule_id="R-007",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_MEDIUM,
        pattern=_re(r"\bchown\s+-R\b"),
        description="Recursive ownership change is hard to undo",
        safe_alternative="Restrict chown -R to a specific application directory",
    ),

    # R-008: rm -rf <anything> (catch-all for application data deletion)
    IntentRule(
        rule_id="R-008",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_MEDIUM,
        pattern=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|"
            r"-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive)\b"
        ),
        description="Recursive force-delete of application data is irreversible",
        safe_alternative="Confirm the target path; back up before delete",
    ),

    # R-009: clear logs (truncate or vacuum, NOT delete)
    IntentRule(
        rule_id="R-009",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_MEDIUM,
        pattern=_re(
            r"(?:>\s*/var/log/[A-Za-z0-9_.\-/]+|"
            r"\btruncate\b\s+-s\s+0\s+/var/log/|"
            r"\bjournalctl\b\s+--vacuum-(?:size|time|files))"
        ),
        description="Clearing log files erases recent diagnostics",
        safe_alternative="Rotate via logrotate or archive before truncation",
    ),

    # R-010: chattr -i (remove immutable flag)
    IntentRule(
        rule_id="R-010",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(r"\bchattr\s+(?:-[a-zA-Z]*i[a-zA-Z]*)\b"),
        description="Removing the immutable flag (-i) from system files enables tampering",
        safe_alternative=(
            "Run 'lsattr <file>' first to inspect flags; "
            "immutable files should only be modified during maintenance windows"
        ),
    ),

    # R-011: setfacl (ACL manipulation)
    IntentRule(
        rule_id="R-011",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"\bsetfacl\s+(?:-m|-x|--modify|--remove)\b"
        ),
        description="Modifying ACLs can create privilege escalation paths",
        safe_alternative=(
            "Review current ACLs with 'getfacl <path>' before making changes; "
            "ensure the change does not grant unexpected access"
        ),
    ),

    # R-012: nsenter container escape
    IntentRule(
        rule_id="R-012",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\bnsenter\s+(?:-[a-zA-Z]*t[a-zA-Z]*\s+\d+|"
            r"--target\s+\d+)"
        ),
        description="Entering another process's namespace can escape container isolation",
        safe_alternative=(
            "Use 'docker exec' or 'crictl exec' for container inspection; "
            "nsenter should only be used during incident response with explicit approval"
        ),
    ),

    # R-013: docker run --privileged / --pid=host
    IntentRule(
        rule_id="R-013",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_CRITICAL,
        pattern=_re(
            r"\b(?:docker|podman|nerdctl)\s+(?:run|create)\b"
            r"[^|;&]*--(?:privileged|pid=host)\b"
        ),
        description="Launching a privileged container grants near-host-level access",
        safe_alternative=(
            "Drop --privileged; specify individual capabilities with --cap-add "
            "and use --security-opt=no-new-privileges"
        ),
    ),

    # R-014: sysctl -w (kernel parameter modification)
    IntentRule(
        rule_id="R-014",
        decision=DECISION_REQUIRE_APPROVAL,
        risk_level=RISK_HIGH,
        pattern=_re(
            r"\bsysctl\s+(?:-[a-zA-Z]*w[a-zA-Z]*|--write)\b"
        ),
        description="Modifying kernel parameters can destabilize the system or weaken security",
        safe_alternative=(
            "Read current values with 'sysctl <param>'; "
            "kernel parameter changes should be done via /etc/sysctl.d/ with review"
        ),
    ),

    # =========================================================================
    # ALLOW rules - all anchored at start so chained commands fall through
    # to BLOCK / REQUIRE_APPROVAL / default-approval. The validator further
    # disables ALLOW matching when the command contains shell-chain operators.
    # =========================================================================

    IntentRule(
        rule_id="A-001",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?ps\b"),
        description="Read-only process listing (ps)",
    ),
    IntentRule(
        rule_id="A-002",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?(?:top|htop)\b"),
        description="Read-only process monitor (top / htop)",
    ),
    IntentRule(
        rule_id="A-003",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?df\b"),
        description="Read-only disk usage (df)",
    ),
    IntentRule(
        rule_id="A-004",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?free\b"),
        description="Read-only memory snapshot (free)",
    ),
    IntentRule(
        rule_id="A-005",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?uptime\b"),
        description="Read-only uptime",
    ),
    IntentRule(
        rule_id="A-006",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?journalctl\b"),
        description="Read-only journal viewer (vacuum/rotate variants are caught by R-009)",
    ),
    IntentRule(
        rule_id="A-007",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?ss\b"),
        description="Read-only socket statistics (ss)",
    ),
    IntentRule(
        rule_id="A-008",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?netstat\b"),
        description="Read-only network status (netstat)",
    ),
    IntentRule(
        rule_id="A-009",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(r"^\s*(?:sudo\s+)?lsof\b"),
        description="Read-only open-file listing (lsof)",
    ),
    IntentRule(
        rule_id="A-010",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(
            r"^\s*(?:sudo\s+)?systemctl\s+"
            r"(?:status|is-active|is-enabled|is-failed|"
            r"list-units|list-unit-files|show|cat)\b"
        ),
        description="Read-only systemd queries",
    ),
    # A-011: bonus safe extras (uname / whoami / id / hostname / pwd / date /
    # who / last / cat /etc/os-release / cat /proc/<safe>) - never blocked
    # by spec, always benign for an OPS agent.
    IntentRule(
        rule_id="A-011",
        decision=DECISION_ALLOW,
        risk_level=RISK_LOW,
        pattern=_re(
            r"^\s*(?:sudo\s+)?(?:"
            r"uname|whoami|id|hostname|pwd|date|who|last|"
            r"cat\s+/etc/os-release\b|"
            r"cat\s+/proc/(?:meminfo|loadavg|cpuinfo|uptime)\b"
            r")"
        ),
        description="Read-only host information query",
    ),
)


def get_rules() -> tuple[IntentRule, ...]:
    """Return the immutable rule catalogue."""
    return RULES


__all__ = [
    "DECISION_ALLOW",
    "DECISION_REQUIRE_APPROVAL",
    "DECISION_BLOCK",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "DECISION_RANK",
    "RISK_RANK",
    "DANGER_DESTRUCTIVE_ROOT",
    "DANGER_PERMISSION_777",
    "DANGER_PERMISSION_CHOWN_ROOT",
    "DANGER_FS_FORMAT",
    "DANGER_DISK_OVERWRITE",
    "DANGER_HOST_OFFLINE",
    "DANGER_REMOTE_SCRIPT_EXEC",
    "DANGER_FORK_BOMB",
    "DANGER_FIREWALL_FLUSH",
    "DANGER_FIREWALL_PERMANENT_REMOVE",
    "DANGER_K8S_DELETE_NS",
    "DANGER_K8S_DELETE_ALL",
    "DANGER_LOG_DESTRUCTION",
    "DANGER_KYLINSEC_DISABLE",
    "DANGER_TCM_TAMPER",
    "DANGER_BOOT_CHAIN_BREAK",
    "DANGER_REPO_TAMPER",
    "DANGER_UNSIGNED_MODULE",
    "DANGER_IMA_POLICY_TAMPER",
    "DANGER_AUDIT_DISABLE",
    "DANGER_FIRMWARE_WRITE",
    "DANGER_CATEGORY_LABELS",
    "IntentRule",
    "RULES",
    "get_rules",
]
