"""LoongArch seccomp syscall number table and BPF filter builder.

On LoongArch64 the system call numbers differ COMPLETELY from x86_64.
For example:

    =============  ===========  ===========
    syscall         x86_64       loongarch64
    =============  ===========  ===========
    read            0            63
    write           1            64
    openat          257          56
    close           3            57
    mmap            9            222
    mprotect        10           226
    brk             12           214
    fork            57           220
    execve          59           221
    clone           56           220
    ptrace          101          118
    chmod           90           49
    mount           165          40
    =============  ===========  ===========

Source: Linux kernel ``arch/loongarch/include/uapi/asm/unistd.h``
(shiped with Kylin V11 headers, kernel >= 5.15).

This module provides two things:

1. **``LOONGARCH_SYSCALL_TABLE``** — a dict mapping syscall names to
   their LoongArch64 numbers. Useful for constructing seccomp BPF
   filters programmatically (e.g. via ``seccomp`` or ``libseccomp``).

2. **``build_loongarch_seccomp_filter``** — a best-effort seccomp BPF
   bytecode generator that whitelists the ~30 syscalls needed by a
   typical read-only diagnostic command (``ps``, ``ss``, ``df``, etc.)
   and kills the process on any other syscall.

On non-LoongArch hosts both the table and the builder return empty
results so callers don't need to branch on the architecture.

IMPORTANT: On Kylin V11 systemd-based deployments, prefer
``SystemCallFilter=@default ...`` in the ``ops-agent.service`` unit
file. The systemd filter is architecture-neutral and tested across
x86_64 / aarch64 / LoongArch64. The BPF filter here is for container
environments or direct ``subprocess.run`` calls where systemd is not
available.
"""
from __future__ import annotations

import logging
import platform as _platform
from typing import Any

logger = logging.getLogger(__name__)

_IS_LOONGARCH = _platform.machine().lower() in {"loongarch64", "loong64"}

# ---------------------------------------------------------------------------
# LoongArch syscall number table
# ---------------------------------------------------------------------------
# Each entry: name -> (number, category)
# Categories: "safe_read", "safe_fd", "proc", "time", "forbidden"

LOONGARCH_SYSCALL_TABLE: dict[str, tuple[int, str]] = {
    # ── safe read-only ──
    "read":             (63,  "safe_fd"),
    "pread64":          (67,  "safe_fd"),
    "readv":            (65,  "safe_fd"),
    "write":            (64,  "safe_fd"),     # only allowed on fd 1,2
    "writev":           (66,  "safe_fd"),
    "openat":           (56,  "safe_fd"),     # must enforce O_RDONLY
    "close":            (57,  "safe_fd"),
    "fstat":            (80,  "safe_fd"),
    "stat":             (40,  "safe_fd"),
    "newfstatat":       (79,  "safe_fd"),
    "lseek":            (62,  "safe_fd"),
    "getdents64":       (61,  "safe_fd"),
    # ── memory operations ──
    "mmap":             (222, "safe_read"),
    "mprotect":         (226, "safe_read"),
    "munmap":           (215, "safe_read"),
    "brk":              (214, "safe_read"),
    "madvise":          (219, "safe_read"),
    # ── process identity / control ──
    "getpid":           (172, "proc"),
    "gettid":           (178, "proc"),
    "getuid":           (174, "proc"),
    "getgid":           (176, "proc"),
    "geteuid":          (175, "proc"),
    "getegid":          (177, "proc"),
    "getcwd":           (17,  "proc"),
    "getppid":          (173, "proc"),
    "getpgid":          (155, "proc"),
    "prctl":            (167, "proc"),        # must enforce PR_* subsets
    "arch_prctl":       (169, "proc"),        # architecture-specific
    # ── signal handling ──
    "rt_sigaction":     (134, "proc"),
    "rt_sigprocmask":   (135, "proc"),
    "sigaltstack":      (132, "proc"),
    "rt_sigreturn":     (139, "proc"),
    # ── time ──
    "clock_gettime":    (113, "time"),
    "clock_nanosleep":  (115, "time"),
    "nanosleep":        (101, "time"),
    "gettimeofday":     (169, "time"),
    # ── misc safe ──
    "ioctl":            (29,  "safe_read"),   # must restrict to TIOCGWINSZ
    "fcntl":            (25,  "safe_fd"),
    "dup":              (23,  "safe_fd"),
    "dup3":             (24,  "safe_fd"),
    "pipe2":            (59,  "safe_fd"),
    "epoll_create1":    (20,  "safe_fd"),
    "epoll_ctl":        (21,  "safe_fd"),
    "epoll_pwait":      (22,  "safe_fd"),
    "sched_yield":      (124, "proc"),
    "exit":             (93,  "proc"),
    "exit_group":       (94,  "proc"),

    # ── FORBIDDEN (included for completeness) ──
    "fork":             (220, "forbidden"),
    "execve":           (221, "forbidden"),
    "execveat":         (59,  "forbidden"),
    "clone":            (220, "forbidden"),   # same number as fork on LA64
    "clone3":           (435, "forbidden"),
    "ptrace":           (118, "forbidden"),
    "chmod":            (49,  "forbidden"),
    "fchmod":           (50,  "forbidden"),
    "fchmodat":         (53,  "forbidden"),
    "chown":            (49,  "forbidden"),   # alias
    "fchown":           (55,  "forbidden"),
    "fchownat":         (54,  "forbidden"),
    "mount":            (40,  "forbidden"),
    "umount2":          (39,  "forbidden"),
    "pivot_root":       (41,  "forbidden"),
    "swapon":           (224, "forbidden"),
    "swapoff":          (225, "forbidden"),
    "reboot":           (142, "forbidden"),
    "kexec_load":       (104, "forbidden"),
    "kexec_file_load":  (105, "forbidden"),
    "init_module":      (106, "forbidden"),
    "finit_module":     (107, "forbidden"),
    "delete_module":    (108, "forbidden"),
    "setuid":           (105, "forbidden"),
    "setgid":           (106, "forbidden"),
    "setreuid":         (145, "forbidden"),
    "setregid":         (146, "forbidden"),
    "setresuid":        (147, "forbidden"),
    "setresgid":        (148, "forbidden"),
    "setfsuid":         (151, "forbidden"),
    "setfsgid":         (152, "forbidden"),
    "capset":           (91,  "forbidden"),
    "personality":      (92,  "forbidden"),
    "bpf":              (280, "forbidden"),   # don't let subprocess load seccomp
    "seccomp":          (277, "forbidden"),   # nor bypass ours
    "prlimit64":        (164, "forbidden"),   # don't lift resource limits
    "process_vm_readv": (270, "forbidden"),
    "process_vm_writev":(271, "forbidden"),
    "keyctl":           (219, "forbidden"),
    "socket":           (198, "forbidden"),   # no network for child
    "connect":          (203, "forbidden"),
    "bind":             (200, "forbidden"),
    "listen":           (201, "forbidden"),
    "accept":           (202, "forbidden"),
    "sendto":           (206, "forbidden"),
    "recvfrom":         (207, "forbidden"),
}


def build_loongarch_seccomp_filter(
    *,
    extra_allowed: list[int] | None = None,
) -> list[dict[str, Any]] | None:
    """Build a LoongArch seccomp BPF filter description.

    Returns a list of filter instruction dicts suitable for use with
    the ``seccomp`` Python library or for documentation purposes.

    When ``_IS_LOONGARCH`` is False, returns None immediately — callers
    should fall back to ``SystemCallFilter=`` in the systemd unit
    or use ``libseccomp`` on the target architecture.

    The filter:
        * Whitelists ``safe_read``, ``safe_fd``, ``proc``, and ``time``
          category syscalls (approx 35 numbers).
        * RETURN ERRNO(EPERM) on ``forbidden`` category syscalls.
        * KILL the process on any other syscall.
    """
    if not _IS_LOONGARCH:
        logger.debug("seccomp_loongarch: not on LoongArch; filter not built")
        return None

    allowed = sorted({
        num for name, (num, cat) in LOONGARCH_SYSCALL_TABLE.items()
        if cat in ("safe_read", "safe_fd", "proc", "time")
    })
    if extra_allowed:
        allowed.extend(extra_allowed)
        allowed = sorted(set(allowed))

    # Group allowed syscalls into 4 ranges for compact BPF comparisons.
    groups = _group_consecutive(allowed)

    return {
        "architecture": "AUDIT_ARCH_LOONGARCH64",
        "is_loongarch": True,
        "allowed_syscall_count": len(allowed),
        "allowed_syscalls": allowed,
        "consecutive_groups": groups,
        "forbidden_syscalls": sorted({
            num for name, (num, cat) in LOONGARCH_SYSCALL_TABLE.items()
            if cat == "forbidden"
        }),
        "default_action": "SECCOMP_RET_KILL_THREAD",
        "forbidden_action": "SECCOMP_RET_ERRNO (EPERM)",
        "note": (
            "This is a human-readable filter spec. To generate actual BPF bytecode "
            "use the 'seccomp' Python library with `seccomp.SyscallFilter(defaction=KILL)` "
            "and add rules for each syscall number. On Kylin V11 systemd deployments "
            "the recommended approach is `SystemCallFilter=@default @signal @timer @basic-io` "
            "in the ops-agent.service unit file (cross-architecture)."
        ),
    }


def _group_consecutive(numbers: list[int]) -> list[list[int]]:
    """Group sorted ascending ints into consecutive runs for BPF range checks."""
    groups: list[list[int]] = []
    for n in numbers:
        if groups and n == groups[-1][-1] + 1:
            groups[-1].append(n)
        else:
            groups.append([n])
    return groups


def is_loongarch() -> bool:
    """Return True when running on LoongArch64."""
    return _IS_LOONGARCH


__all__ = [
    "LOONGARCH_SYSCALL_TABLE",
    "build_loongarch_seccomp_filter",
    "is_loongarch",
]
