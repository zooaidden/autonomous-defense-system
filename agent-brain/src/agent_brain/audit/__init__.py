"""Audit package - JSONL audit log for the OPS request lifecycle.

Imports here re-export the public surface so callers can write::

    from agent_brain.audit import OpsAuditLog, new_request_id, ...

This package has no FastAPI / network / LLM dependencies and is safe
to import from any module in agent-brain.

Two sinks live here:

* :class:`OpsAuditLog`  - append-only JSONL stream (per-event, used by
  the OPS orchestrator and ``GET /ops/audit/{id}`` replay).
* :class:`AuditLogger`  - per-request consolidated JSON file writer
  (used by ``POST /ops/chat`` and ``POST /workflow/run`` to populate
  the ``auditFile`` response field).
"""
from agent_brain.audit.audit_logger import (
    WORKFLOW_OS_OPS,
    WORKFLOW_SECURITY_DEFENSE,
    AuditLogger,
    get_default_audit_logger,
    new_workflow_request_id,
    reset_default_audit_logger,
)
from agent_brain.audit.kylin_audit_bridge import KylinAuditBridge
from agent_brain.audit.ops_audit_log import (
    STAGE_APPROVED,
    STAGE_BLOCKED,
    STAGE_COMPLETED,
    STAGE_CONFIG_GUARD_BLOCKED,
    STAGE_DANGEROUS_INTENT_DETECTED,
    STAGE_DENIED,
    STAGE_ERROR,
    STAGE_EXECUTED,
    STAGE_EXECUTION_SKIPPED,
    STAGE_INVALID_INPUT,
    STAGE_PENDING_APPROVAL,
    STAGE_PROMPT_INJECTION_DETECTED,
    STAGE_REJECTED,
    STAGE_REQUEST_RECEIVED,
    STAGE_RUNTIME_ERROR,
    STAGE_TIMEOUT,
    STAGE_VALIDATED,
    OpsAuditLog,
    get_default_audit_log,
    new_request_id,
    reset_default_audit_log,
    stage_from_executor_envelope,
    stage_from_validator_envelope,
)
from agent_brain.audit.tcm_integrity import (
    TCMIntegrityGuard,
    get_default_guard,
)

__all__ = [
    # ops_audit_log
    "STAGE_APPROVED",
    "STAGE_BLOCKED",
    "STAGE_COMPLETED",
    "STAGE_CONFIG_GUARD_BLOCKED",
    "STAGE_DANGEROUS_INTENT_DETECTED",
    "STAGE_DENIED",
    "STAGE_ERROR",
    "STAGE_EXECUTED",
    "STAGE_EXECUTION_SKIPPED",
    "STAGE_INVALID_INPUT",
    "STAGE_PENDING_APPROVAL",
    "STAGE_PROMPT_INJECTION_DETECTED",
    "STAGE_REJECTED",
    "STAGE_REQUEST_RECEIVED",
    "STAGE_RUNTIME_ERROR",
    "STAGE_TIMEOUT",
    "STAGE_VALIDATED",
    "OpsAuditLog",
    "get_default_audit_log",
    "new_request_id",
    "reset_default_audit_log",
    "stage_from_executor_envelope",
    "stage_from_validator_envelope",
    # audit_logger
    "AuditLogger",
    "WORKFLOW_OS_OPS",
    "WORKFLOW_SECURITY_DEFENSE",
    "get_default_audit_logger",
    "new_workflow_request_id",
    "reset_default_audit_logger",
    # tcm_integrity
    "TCMIntegrityGuard",
    "get_default_guard",
    # kylin_audit_bridge
    "KylinAuditBridge",
]
