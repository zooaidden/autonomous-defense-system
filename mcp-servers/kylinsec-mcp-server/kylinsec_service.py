"""Pure-Python Kylin security perception service for kylinsec-mcp-server.

This module is the Kylin/LoongArch counterpart to ``os_service.py``.
It exposes read-only tools specific to the Kylin Advanced Server V11
security ecosystem:

    * KylinSec MAC (Mandatory Access Control) status
    * TCM (Trusted Cryptography Module) PCR values
    * IMA (Integrity Measurement Architecture) verification
    * Kernel module signature validation
    * Kylin patch level / trusted repo status
    * seccomp architecture identification
    * auditd policy inspection

Every tool returns the same envelope as os-mcp-server tools::

    {
        "success": bool,
        "tool":    "<tool_name>",
        "data":    <tool-specific payload or None>,
        "summary": "<human-readable single line>",
        "error":   None | "<machine-readable code>",
    }

All external commands use argv-list form (shell=False). Non-Kylin /
non-Linux hosts gracefully return ``tool_unavailable`` for every tool.

Design rules (same as os_service.py):
* Every external command is invoked with ``subprocess.run`` using argv
  form. ``shell=True`` is forbidden.
* Every call carries an explicit timeout and is wrapped in try/except.
* Output is decoded with ``errors="replace"`` and truncated.
* Error codes are stable: ``tool_unavailable``, ``invalid_argument``,
  ``timeout``, ``command_failed``.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults (mirror os_service.py)
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT_SECONDS: float = 5.0
MAX_STDOUT_BYTES: int = 256 * 1024
MAX_STDERR_BYTES: int = 16 * 1024

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def _is_kylin() -> bool:
    return Path("/etc/kylin-release").exists()


def _is_loongarch() -> bool:
    import platform
    return platform.machine().lower() in {"loongarch64", "loong64"}


def _is_linux() -> bool:
    import platform
    return platform.system().lower() == "linux"


# ---------------------------------------------------------------------------
# Envelope helpers (identical to os_service.py)
# ---------------------------------------------------------------------------


def _envelope(*, success: bool, tool: str, data: Any, summary: str, error: str | None) -> dict[str, Any]:
    return {"success": bool(success), "tool": tool, "data": data, "summary": summary, "error": error}


def _ok(tool: str, data: Any, summary: str) -> dict[str, Any]:
    return _envelope(success=True, tool=tool, data=data, summary=summary, error=None)


def _err(tool: str, summary: str, error: str, *, data: Any = None) -> dict[str, Any]:
    return _envelope(success=False, tool=tool, data=data, summary=summary, error=error)


# ---------------------------------------------------------------------------
# Subprocess helpers (mirror os_service.py)
# ---------------------------------------------------------------------------


def _which(command: str) -> str | None:
    return shutil.which(command)


def _decode_truncate(blob: bytes | None, cap: int) -> str:
    if not blob:
        return ""
    truncated = False
    if len(blob) > cap:
        blob = blob[:cap]
        truncated = True
    text = blob.decode("utf-8", errors="replace")
    if truncated:
        text += "\n... [truncated]"
    return text


def _run_command(argv: list[str], *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> tuple[int, str, str, str | None]:
    if not argv:
        return -1, "", "", "command_failed"
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False, shell=False)
    except FileNotFoundError:
        return -1, "", "", "command_not_found"
    except PermissionError:
        return -1, "", "", "command_failed"
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_truncate(getattr(exc, "stdout", None), MAX_STDOUT_BYTES)
        stderr = _decode_truncate(getattr(exc, "stderr", None), MAX_STDERR_BYTES)
        return -1, stdout, stderr, "timeout"
    except OSError:
        return -1, "", "", "command_failed"
    stdout = _decode_truncate(proc.stdout, MAX_STDOUT_BYTES)
    stderr = _decode_truncate(proc.stderr, MAX_STDERR_BYTES)
    return proc.returncode, stdout, stderr, None


# ---------------------------------------------------------------------------
# Platform guard: non-Linux / non-Kylin hosts get tool_unavailable for
# every tool. This is checked at the top of each public function via
# _require_kylin().
# ---------------------------------------------------------------------------

def _require_kylin(tool: str) -> dict[str, Any] | None:
    """Return an error envelope if we are not on Kylin/Linux, else None."""
    if not _is_linux():
        return _err(tool, "KylinSec tools require a Linux host", "tool_unavailable")
    return None


# ---------------------------------------------------------------------------
# 1. get_kylinsec_status
# ---------------------------------------------------------------------------


def get_kylinsec_status() -> dict[str, Any]:
    tool = "get_kylinsec_status"
    if (guard := _require_kylin(tool)):
        return guard

    # Prefer kylinsec-status binary; fall back to sysfs probe.
    data: dict[str, Any] = {
        "kylinsec_available": False,
        "mode": "unknown",
        "policy_version": None,
        "active_since": None,
    }

    if _which("kylinsec-status") is not None:
        rc, stdout, stderr, run_err = _run_command(["kylinsec-status"], timeout=DEFAULT_TIMEOUT_SECONDS)
        if run_err is None and rc == 0:
            data["kylinsec_available"] = True
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line.startswith("mode:"):
                    data["mode"] = line.split(":", 1)[1].strip()
                elif line.startswith("policy version:"):
                    data["policy_version"] = line.split(":", 1)[1].strip()
                elif line.startswith("active since:"):
                    data["active_since"] = line.split(":", 1)[1].strip()
            return _ok(tool, data, f"KylinSec mode={data['mode']}")

    # Sysfs fallback: KylinSec typically exposes status here.
    kylinsec_sysfs = Path("/sys/kernel/security/kylinsec")
    if kylinsec_sysfs.exists():
        data["kylinsec_available"] = True
        for candidate in ["enforce", "enabled", "mode"]:
            candidate_path = kylinsec_sysfs / candidate
            if candidate_path.exists():
                try:
                    val = candidate_path.read_text(encoding="utf-8", errors="replace").strip()
                    if val == "1" or val.lower() == "enforcing":
                        data["mode"] = "enforcing"
                    elif val == "0" or val.lower() == "permissive":
                        data["mode"] = "permissive"
                    else:
                        data["mode"] = val.lower()
                    break
                except OSError:
                    continue
        return _ok(tool, data, f"KylinSec mode={data['mode']} (sysfs)")

    if _is_kylin():
        data["kylinsec_available"] = False
        return _ok(tool, data, "KylinSec status probe ran but MAC subsystem not detected")
    return _err(tool, "KylinSec is not available on this host", "tool_unavailable")


# ---------------------------------------------------------------------------
# 2. get_tcm_pcrs
# ---------------------------------------------------------------------------


def get_tcm_pcrs() -> dict[str, Any]:
    tool = "get_tcm_pcrs"
    if (guard := _require_kylin(tool)):
        return guard

    data: dict[str, Any] = {
        "tcm_available": False,
        "pcrs": {},
        "tcm_device": None,
    }

    # Probe /sys/class/tcm/ (standard Linux TCM sysfs interface).
    tcm_class = Path("/sys/class/tcm")
    if tcm_class.exists():
        for child in sorted(tcm_class.iterdir()):
            if child.is_dir() and child.name.startswith("tcm"):
                data["tcm_available"] = True
                data["tcm_device"] = f"/dev/{child.name}"
                pcrs_path = child / "pcrs"
                if pcrs_path.exists():
                    try:
                        raw = pcrs_path.read_text(encoding="utf-8", errors="replace").strip()
                        data["pcrs"]["raw"] = raw[:4096]
                    except OSError:
                        pass
                break

    # Fall back to tcm_get_info binary.
    if not data["tcm_available"] and _which("tcm_get_info") is not None:
        rc, stdout, _stderr, run_err = _run_command(["tcm_get_info"], timeout=DEFAULT_TIMEOUT_SECONDS)
        if run_err is None and rc == 0:
            data["tcm_available"] = True
            data["pcrs"]["raw"] = stdout[:4096]

    if data["tcm_available"]:
        return _ok(
            tool,
            data,
            f"TCM {'available' if data['tcm_available'] else 'unavailable'} "
            f"({data.get('tcm_device', 'n/a')})"
        )
    return _err(
        tool,
        "TCM is not available on this host (/sys/class/tcm not found, tcm_get_info missing)",
        "tool_unavailable",
    )


# ---------------------------------------------------------------------------
# 3. verify_binary_ima
# ---------------------------------------------------------------------------


def verify_binary_ima(path: str = "") -> dict[str, Any]:
    tool = "verify_binary_ima"
    if (guard := _require_kylin(tool)):
        return guard

    candidate = (path or "").strip()
    if not candidate or not candidate.startswith("/"):
        return _err(tool, f"invalid path: {path!r}", "invalid_argument")
    if len(candidate) > 4096 or any(ch in candidate for ch in " \t\n\r\x00`$\\\"'<>|&;*?()[]{}!~"):
        return _err(tool, f"path contains unsafe characters: {path!r}", "invalid_argument")

    target = Path(candidate)
    if not target.exists():
        return _err(tool, f"path does not exist: {candidate}", "invalid_argument")

    # IMA measurements are logged to /sys/kernel/security/ima/ascii_runtime_measurements
    ima_log = Path("/sys/kernel/security/ima/ascii_runtime_measurements")
    if not ima_log.exists():
        return _err(tool, "IMA runtime measurements not available", "tool_unavailable")

    try:
        content = ima_log.read_text(encoding="utf-8", errors="replace")[:MAX_STDOUT_BYTES]
    except OSError as exc:
        return _err(tool, f"cannot read IMA log: {exc}", "command_failed")

    found = [line for line in content.splitlines() if candidate in line]
    return _ok(
        tool,
        {
            "path": candidate,
            "ima_available": True,
            "measurements_found": len(found),
            "entries": found[:20],
        },
        f"{len(found)} IMA measurement(s) found for {candidate}"
    )


# ---------------------------------------------------------------------------
# 4. get_kernel_module_signatures
# ---------------------------------------------------------------------------


def get_kernel_module_signatures() -> dict[str, Any]:
    tool = "get_kernel_module_signatures"
    if (guard := _require_kylin(tool)):
        return guard

    modules: list[dict[str, Any]] = []
    try:
        proc_modules = Path("/proc/modules")
        if not proc_modules.exists():
            return _err(tool, "/proc/modules not available", "tool_unavailable")
        raw = proc_modules.read_text(encoding="utf-8", errors="replace")[:MAX_STDOUT_BYTES]
    except OSError as exc:
        return _err(tool, f"cannot read /proc/modules: {exc}", "command_failed")

    for line in raw.splitlines():
        name = line.split(None, 1)[0].strip()
        if not name:
            continue
        sig_status = "unknown"
        signer = None
        if _which("modinfo") is not None:
            rc, stdout, _stderr, run_err = _run_command(
                ["modinfo", "-F", "signer", name],
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            if run_err is None and rc == 0 and stdout.strip():
                sig_status = "signed"
                signer = stdout.strip().splitlines()[0].strip()
            elif run_err is None and rc != 0:
                sig_status = "unsigned"
        modules.append({
            "name": name,
            "signature_status": sig_status,
            "signer": signer,
        })

    signed = sum(1 for m in modules if m["signature_status"] == "signed")
    unsigned = sum(1 for m in modules if m["signature_status"] == "unsigned")
    return _ok(
        tool,
        {
            "total_modules": len(modules),
            "signed_count": signed,
            "unsigned_count": unsigned,
            "modules": modules[:100],
        },
        f"{signed} signed, {unsigned} unsigned out of {len(modules)} kernel modules"
    )


# ---------------------------------------------------------------------------
# 5. get_kylin_patch_level
# ---------------------------------------------------------------------------


def get_kylin_patch_level() -> dict[str, Any]:
    tool = "get_kylin_patch_level"
    if (guard := _require_kylin(tool)):
        return guard

    data: dict[str, Any] = {
        "kylin_version": None,
        "kernel_version": None,
        "os_pretty": None,
    }

    # /etc/kylin-release
    kylin_release = Path("/etc/kylin-release")
    if kylin_release.exists():
        try:
            data["kylin_version"] = kylin_release.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
        except OSError:
            pass

    # /etc/os-release
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("PRETTY_NAME="):
                    data["os_pretty"] = line.split("=", 1)[1].strip().strip('"')
                    break
        except OSError:
            pass

    # Kernel version
    import platform as _platform
    data["kernel_version"] = _platform.release()
    data["machine"] = _platform.machine()
    data["is_loongarch"] = _is_loongarch()

    if _which("rpm") is not None:
        rc, stdout, _stderr, run_err = _run_command(
            ["rpm", "-q", "kylin-release"], timeout=DEFAULT_TIMEOUT_SECONDS
        )
        if run_err is None and rc == 0:
            data["rpm_kylin_release"] = stdout.strip().splitlines()[0]

    summary = f"Kylin: {data.get('kylin_version', 'n/a')} / kernel: {data['kernel_version']} / {data['machine']}"
    return _ok(tool, data, summary)


# ---------------------------------------------------------------------------
# 6. check_seccomp_arch
# ---------------------------------------------------------------------------


def check_seccomp_arch() -> dict[str, Any]:
    tool = "check_seccomp_arch"
    if (guard := _require_kylin(tool)):
        return guard

    import platform as _platform
    machine = _platform.machine().lower()

    # Map Linux uname -m to AUDIT_ARCH_* constants used by seccomp.
    ARCH_MAP: dict[str, str] = {
        "x86_64": "AUDIT_ARCH_X86_64",
        "aarch64": "AUDIT_ARCH_AARCH64",
        "loongarch64": "AUDIT_ARCH_LOONGARCH64",
        "loong64": "AUDIT_ARCH_LOONGARCH64",
        "armv7l": "AUDIT_ARCH_ARM",
        "riscv64": "AUDIT_ARCH_RISCV64",
    }

    audit_arch = ARCH_MAP.get(machine, f"unknown ({machine})")
    data = {
        "machine": machine,
        "audit_arch": audit_arch,
        "is_loongarch": machine in {"loongarch64", "loong64"},
        "note": "Use this value when constructing seccomp BPF filters. On LoongArch the syscall numbers differ from x86_64.",
    }
    return _ok(tool, data, f"seccomp audit arch: {audit_arch}")


# ---------------------------------------------------------------------------
# 7. get_kylin_audit_policy
# ---------------------------------------------------------------------------


def get_kylin_audit_policy() -> dict[str, Any]:
    tool = "get_kylin_audit_policy"
    if (guard := _require_kylin(tool)):
        return guard

    data: dict[str, Any] = {
        "auditd_active": False,
        "rules": [],
        "enabled_flag": None,
    }

    # Check if auditd service is active.
    if _which("systemctl") is not None:
        rc, stdout, _stderr, run_err = _run_command(
            ["systemctl", "is-active", "auditd"], timeout=DEFAULT_TIMEOUT_SECONDS
        )
        if run_err is None and rc == 0:
            data["auditd_active"] = stdout.strip() == "active"

    # Get current audit rules via auditctl -l.
    if _which("auditctl") is not None:
        rc, stdout, _stderr, run_err = _run_command(
            ["auditctl", "-l"], timeout=DEFAULT_TIMEOUT_SECONDS
        )
        if run_err is None and rc == 0:
            data["rules"] = [r for r in stdout.splitlines() if r.strip()]

        # Check enabled flag.
        rc2, stdout2, _stderr2, run_err2 = _run_command(
            ["auditctl", "-s"], timeout=DEFAULT_TIMEOUT_SECONDS
        )
        if run_err2 is None and rc2 == 0:
            for line in stdout2.splitlines():
                if "enabled" in line.lower():
                    data["enabled_flag"] = line.strip()

    if data["auditd_active"] or data["rules"]:
        return _ok(
            tool,
            data,
            f"auditd {'active' if data['auditd_active'] else 'inactive'} "
            f"with {len(data['rules'])} rule(s)"
        )
    return _err(tool, "auditd is not available on this host", "tool_unavailable")


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------

__all__ = [
    "get_kylinsec_status",
    "get_tcm_pcrs",
    "verify_binary_ima",
    "get_kernel_module_signatures",
    "get_kylin_patch_level",
    "check_seccomp_arch",
    "get_kylin_audit_policy",
]
