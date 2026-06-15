"""Executors package - safe runtime gates for OPS commands.

Currently exposes :class:`LeastPrivilegeExecutor` (and its helper
constants), which is the only place in agent-brain allowed to invoke
``subprocess.run`` against an OS command on behalf of an OPS request.

Also exposes :class:`SystemdSandbox` and :class:`SandboxLimits` for
Kylin V11 / systemd-based cgroup isolation.

This package has no FastAPI / network / LLM dependencies and is safe
to import from any module in agent-brain.
"""
from agent_brain.executors.least_privilege_executor import (
    DEFAULT_OUTPUT_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    STATUS_BLOCKED,
    STATUS_EXECUTED,
    STATUS_INVALID_INPUT,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    STATUS_RUNTIME_ERROR,
    STATUS_TIMEOUT,
    ExecutorResult,
    LeastPrivilegeExecutor,
    execute_command,
)
from agent_brain.executors.systemd_sandbox import (
    DEFAULT_CPU_QUOTA,
    DEFAULT_MEMORY_MAX,
    DEFAULT_TASKS_MAX,
    SandboxLimits,
    SystemdSandbox,
    wrap_if_available,
)
from agent_brain.executors import seccomp_loongarch

__all__ = [
    "DEFAULT_OUTPUT_LIMIT",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_CPU_QUOTA",
    "DEFAULT_MEMORY_MAX",
    "DEFAULT_TASKS_MAX",
    "STATUS_BLOCKED",
    "STATUS_EXECUTED",
    "STATUS_INVALID_INPUT",
    "STATUS_PENDING_APPROVAL",
    "STATUS_REJECTED",
    "STATUS_RUNTIME_ERROR",
    "STATUS_TIMEOUT",
    "ExecutorResult",
    "LeastPrivilegeExecutor",
    "SandboxLimits",
    "SystemdSandbox",
    "execute_command",
    "wrap_if_available",
    "seccomp_loongarch",
]
