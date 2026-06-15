"""End-to-end OPS chat orchestrator.

Pipeline (canonical six audit-trail steps, in order):

    received_instruction       -> log REQUEST_RECEIVED
    parsed_intent              -> rule-based intent parser
    mcp_context_collected      -> async OS MCP tool calls
    safety_validated           -> safety.validate_intent
    executed_or_blocked        -> least-privilege executor (only on ALLOW)
    final_answer_generated     -> deterministic template answer

Plus three *dangerous-flow* audit events emitted only when the request
trips the safety guardrails:

    dangerous_intent_detected  -> emitted right after parsed_intent when
                                  the intent parser classifies the input as
                                  INTENT_DANGEROUS_COMMAND OR a quick
                                  candidate-command heuristic recognizes a
                                  blacklisted shell verb (rm -rf /, chmod
                                  777, iptables -F, curl|sh, mkfs, dd of=/dev,
                                  shutdown, reboot, halt, poweroff, log wipe).
    safety_validation_blocked  -> emitted right after safety_validated when
                                  the validator returns BLOCK.
    execution_skipped          -> emitted right after executed_or_blocked
                                  when the executor was NOT allowed to run
                                  (BLOCK, REQUIRE_APPROVAL, REJECTED, ...).

The dangerous events are mirrored into the persistent JSONL audit log
via two new stage constants (``STAGE_DANGEROUS_INTENT_DETECTED`` and
``STAGE_EXECUTION_SKIPPED``) so ``GET /ops/audit/{id}`` replays the
full safety story.

Each step is mirrored into two places:

    1. The response's ``auditTrail`` list (UI-friendly, one entry per
       step with ``{step, status, message, timestamp}``; ``summary`` is
       kept as an alias of ``message`` for backwards-compatibility).
    2. The persistent JSONL ``OpsAuditLog`` (one event per *lifecycle*
       stage, suitable for ``GET /ops/audit/{id}`` replay).

The orchestrator is async because :class:`OsMCPClient` exposes async
tool methods. The safety validator and the executor are synchronous;
they run in-line inside the async function (no blocking IO of note).

Decoupling notes
----------------

* ``/workflow/run`` is unaffected: this orchestrator is constructed
  side-by-side with ``DebateOrchestrator`` in ``main.py`` and shares
  no mutable state with it.
* The OS MCP client is the same instance used for ``/health`` probing
  (``_os_client_probe``), so we avoid spawning a second stdio process.
* All collaborators are constructor-injectable so unit tests can drop
  in fakes (see ``tests/test_ops_orchestrator.py``).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_brain.audit import (
    STAGE_COMPLETED,
    STAGE_CONFIG_GUARD_BLOCKED,
    STAGE_DANGEROUS_INTENT_DETECTED,
    STAGE_EXECUTION_SKIPPED,
    STAGE_PROMPT_INJECTION_DETECTED,
    STAGE_REQUEST_RECEIVED,
    OpsAuditLog,
    get_default_audit_log,
    new_request_id,
    stage_from_executor_envelope,
    stage_from_validator_envelope,
)
from agent_brain.executors import LeastPrivilegeExecutor
from agent_brain.safety import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_REQUIRE_APPROVAL,
    IntentValidator,
    evaluate_system_config,
    inspect_prompt_injection,
)
from agent_brain.safety.danger_catalogue import (
    DANGER_HEURISTIC_RE,
)
from agent_brain.services.ops_intent_parser import (
    INTENT_DANGEROUS_COMMAND,
    INTENT_RAW_COMMAND,
    INTENT_UNKNOWN,
    IntentMatch,
    parse_instruction,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol for the OS MCP client (lets us inject a fake in tests)
# ---------------------------------------------------------------------------


class _OsClientProtocol(Protocol):
    """Subset of OsMCPClient methods the orchestrator depends on."""

    async def get_process_list(self, top_n: int = ...) -> dict[str, Any]: ...
    async def get_network_sockets(
        self, state: str = ..., top_n: int = ...
    ) -> dict[str, Any]: ...
    async def get_open_files(
        self, path: str | None = ..., pid: int | None = ..., top_n: int = ...
    ) -> dict[str, Any]: ...
    async def get_system_logs(
        self,
        unit: str | None = ...,
        lines: int = ...,
        since: str | None = ...,
    ) -> dict[str, Any]: ...
    async def get_disk_usage(self) -> dict[str, Any]: ...
    async def get_memory_status(self) -> dict[str, Any]: ...
    async def get_cpu_load(self) -> dict[str, Any]: ...
    async def get_uptime(self) -> dict[str, Any]: ...
    async def get_service_status(self, service_name: str) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class OpsOrchestrator:
    """Run a single ``POST /ops/chat`` request end-to-end."""

    def __init__(
        self,
        *,
        os_client: _OsClientProtocol,
        validator: IntentValidator | None = None,
        executor: LeastPrivilegeExecutor | None = None,
        audit_log: OpsAuditLog | None = None,
        executor_enabled: bool = True,
        actor: str = "system",
    ) -> None:
        self._os = os_client
        self._validator = validator or IntentValidator()
        self._executor = executor or LeastPrivilegeExecutor()
        self._audit = audit_log or get_default_audit_log()
        self._executor_enabled = bool(executor_enabled)
        self._actor = actor

    @property
    def enabled(self) -> bool:
        # Always on; reserved for a future kill switch (e.g. env var).
        return True

    async def chat(self, instruction: str) -> dict[str, Any]:
        """Process one OPS chat turn and return the response envelope."""
        instruction = (instruction or "").strip()
        request_id = new_request_id()
        trail: list[dict[str, Any]] = []

        # ===== Step 1: received_instruction =====
        self._audit.append_stage(
            STAGE_REQUEST_RECEIVED,
            request_id,
            actor=self._actor,
            instruction=instruction,
        )
        trail.append(
            self._trail_entry(
                "received_instruction",
                status="OK",
                message=f"Received OPS instruction ({len(instruction)} chars)",
            )
        )

        # ===== Step 1.5: prompt_injection_inspected =====
        # Runs BEFORE any parsing so a forged template / jailbreak
        # prefix never reaches the intent parser. On BLOCK we
        # short-circuit the whole pipeline.
        injection_envelope = inspect_prompt_injection(instruction).to_dict()
        injection_decision = str(injection_envelope.get("decision", "ALLOW"))
        injection_blocked = injection_decision == DECISION_BLOCK
        if injection_blocked:
            self._audit.append_stage(
                STAGE_PROMPT_INJECTION_DETECTED,
                request_id,
                actor=self._actor,
                instruction=instruction,
                metadata={"promptInjection": injection_envelope},
                reason=str(injection_envelope.get("reason", "")),
            )
            trail.append(
                self._trail_entry(
                    "prompt_injection_detected",
                    status="BLOCK",
                    message=str(
                        injection_envelope.get("reasonZh")
                        or injection_envelope.get("reason")
                        or "Prompt injection blocked."
                    ),
                    payload={
                        "riskLevel": injection_envelope.get("riskLevel"),
                        "matchedRuleIds": [
                            m.get("ruleId")
                            for m in injection_envelope.get("matchedPatterns", [])
                        ],
                    },
                )
            )
            return self._short_circuit(
                request_id=request_id,
                instruction=instruction,
                trail=trail,
                injection_envelope=injection_envelope,
                config_guard_envelope=evaluate_system_config(instruction=instruction).to_dict(),
                source="prompt_injection",
            )

        # ===== Step 2: parsed_intent =====
        intent: IntentMatch = parse_instruction(instruction)
        plan = intent.to_dict()
        candidate_commands = list(plan.get("candidateCommands", []))
        trail.append(
            self._trail_entry(
                "parsed_intent",
                status="OK",
                message=(
                    f"intent={intent.intent_id} "
                    f"label='{intent.intent_label}' "
                    f"commands={len(candidate_commands)}"
                ),
                payload={
                    "intent": intent.intent_id,
                    "intentLabel": intent.intent_label,
                    "candidateCommands": candidate_commands,
                    "extractedParams": plan.get("extractedParams", {}),
                },
            )
        )

        # ===== Step 2.25: config_guard_inspected =====
        # Path-based guard runs AFTER intent parsing (so we know the
        # candidate commands) but BEFORE MCP / executor. BLOCK here
        # short-circuits the pipeline with a synthetic executionResult.
        config_guard_envelope = evaluate_system_config(
            instruction=instruction,
            candidate_commands=candidate_commands,
        ).to_dict()
        config_decision = str(config_guard_envelope.get("decision", "ALLOW"))
        config_blocked = config_decision == DECISION_BLOCK
        if config_blocked:
            self._audit.append_stage(
                STAGE_CONFIG_GUARD_BLOCKED,
                request_id,
                actor=self._actor,
                instruction=instruction,
                candidate_commands=candidate_commands,
                metadata={"configGuard": config_guard_envelope},
                reason=str(config_guard_envelope.get("reason", "")),
            )
            trail.append(
                self._trail_entry(
                    "config_guard_blocked",
                    status="BLOCK",
                    message=str(
                        config_guard_envelope.get("reasonZh")
                        or config_guard_envelope.get("reason")
                        or "System configuration guard blocked the request."
                    ),
                    payload={
                        "riskLevel": config_guard_envelope.get("riskLevel"),
                        "matchedPaths": [
                            m.get("label")
                            for m in config_guard_envelope.get("matchedPaths", [])
                        ],
                        "matchedVerb": config_guard_envelope.get("matchedVerb"),
                    },
                )
            )
            return self._short_circuit(
                request_id=request_id,
                instruction=instruction,
                trail=trail,
                injection_envelope=injection_envelope,
                config_guard_envelope=config_guard_envelope,
                intent=intent,
                candidate_commands=candidate_commands,
                source="config_guard",
            )

        # ===== Step 2.5 (conditional): dangerous_intent_detected =====
        # Two trigger paths:
        #   (a) parser classified as INTENT_DANGEROUS_COMMAND
        #   (b) intent fell through to RAW_COMMAND but the heuristic
        #       still recognizes a blacklisted verb in the candidate
        #       commands (or the raw instruction).
        is_dangerous_intent = intent.intent_id == INTENT_DANGEROUS_COMMAND
        if not is_dangerous_intent:
            is_dangerous_intent = any(
                (cmd and DANGER_HEURISTIC_RE.search(cmd))
                for cmd in candidate_commands
            ) or bool(instruction and DANGER_HEURISTIC_RE.search(instruction))
        danger_category: str | None = None
        if is_dangerous_intent:
            danger_category = (
                str(intent.extracted_params.get("category"))
                if intent.intent_id == INTENT_DANGEROUS_COMMAND
                else "raw_dangerous_command"
            )
            danger_message = (
                f"Detected dangerous intent (category={danger_category}); "
                f"forwarding to safety validator. Host will not be touched."
            )
            self._audit.append_stage(
                STAGE_DANGEROUS_INTENT_DETECTED,
                request_id,
                actor=self._actor,
                instruction=instruction,
                candidate_commands=candidate_commands,
                metadata={
                    "category": danger_category,
                    "intent": intent.intent_id,
                },
                reason=danger_message,
            )
            trail.append(
                self._trail_entry(
                    "dangerous_intent_detected",
                    status="DETECTED",
                    message=danger_message,
                    payload={
                        "category": danger_category,
                        "candidateCommands": candidate_commands,
                    },
                )
            )

        # ===== Step 3: mcp_context_collected =====
        # Skip MCP fan-out when we already know the request is dangerous
        # so we never accidentally probe the OS for a request we plan to
        # block; emit an explicit "skipped" entry so the timeline stays
        # complete.
        if is_dangerous_intent:
            mcp_trace: list[dict[str, Any]] = []
            trail.append(
                self._trail_entry(
                    "mcp_context_collected",
                    status="SKIPPED",
                    message=(
                        "MCP context collection skipped because the request "
                        "was flagged as dangerous"
                    ),
                )
            )
        else:
            mcp_trace = await self._collect_mcp_context(intent.mcp_tools)
            trail.append(
                self._trail_entry(
                    "mcp_context_collected",
                    status="OK",
                    message=(
                        f"called {len(mcp_trace)} MCP tool(s); "
                        f"successes={sum(1 for t in mcp_trace if t['success'])}"
                    ),
                    payload={
                        "tools": [
                            {
                                "server": t["server"],
                                "tool": t["tool"],
                                "success": t["success"],
                                "summary": t["summary"],
                            }
                            for t in mcp_trace
                        ]
                    },
                )
            )

        # ===== Step 4: safety_validated =====
        validator_envelope = self._validator.validate(
            instruction=instruction,
            candidate_commands=candidate_commands,
        )
        decision = validator_envelope.get("decision", "")
        risk_level = validator_envelope.get("riskLevel", "")
        self._audit.append_stage(
            stage_from_validator_envelope(validator_envelope),
            request_id,
            actor=self._actor,
            instruction=instruction,
            candidate_commands=candidate_commands,
            validator=validator_envelope,
            reason=str(validator_envelope.get("reason", "")),
        )
        trail.append(
            self._trail_entry(
                "safety_validated",
                status=str(decision or "UNKNOWN"),
                message=f"decision={decision} riskLevel={risk_level}",
                payload={
                    "decision": decision,
                    "riskLevel": risk_level,
                    "matchedRuleIds": [
                        m.get("ruleId")
                        for m in validator_envelope.get("matchedRules", [])
                    ],
                },
            )
        )

        # ===== Step 4.5 (conditional): safety_validation_blocked =====
        if decision == DECISION_BLOCK:
            block_message = (
                f"Safety policy BLOCKED execution (risk={risk_level}); "
                f"reason={validator_envelope.get('reason', 'matched BLOCK rule')}"
            )
            trail.append(
                self._trail_entry(
                    "safety_validation_blocked",
                    status="BLOCK",
                    message=block_message,
                    payload={
                        "riskLevel": risk_level,
                        "matchedRuleIds": [
                            m.get("ruleId")
                            for m in validator_envelope.get("matchedRules", [])
                        ],
                        "safeAlternative": validator_envelope.get("safeAlternative"),
                    },
                )
            )

        # ===== Step 5: executed_or_blocked =====
        executor_envelope, exec_summary = self._maybe_execute(
            intent=intent,
            instruction=instruction,
            candidate_commands=candidate_commands,
            validator_envelope=validator_envelope,
            is_dangerous_intent=is_dangerous_intent,
        )
        if executor_envelope is not None:
            self._audit.append_stage(
                stage_from_executor_envelope(executor_envelope),
                request_id,
                actor=self._actor,
                instruction=instruction,
                candidate_commands=candidate_commands,
                validator=validator_envelope,
                executor=executor_envelope,
                reason=str(executor_envelope.get("reason", "")),
            )
        trail.append(
            self._trail_entry(
                "executed_or_blocked",
                status=str(
                    (executor_envelope or {}).get("status", "SKIPPED")
                ),
                message=exec_summary,
                payload={
                    "executorStatus": (
                        executor_envelope.get("status")
                        if executor_envelope
                        else None
                    ),
                    "exitCode": (
                        executor_envelope.get("exitCode")
                        if executor_envelope
                        else None
                    ),
                    "commandId": (
                        executor_envelope.get("commandId")
                        if executor_envelope
                        else None
                    ),
                },
            )
        )

        # ===== Step 5.5 (conditional): execution_skipped =====
        # Emit when the executor was not allowed to actually run a command
        # (BLOCKED, PENDING_APPROVAL, REJECTED, INVALID_INPUT, ...). This
        # gives the UI / audit replay a single, unambiguous record of
        # "no command touched the host".
        executor_status = (
            str(executor_envelope.get("status", "")).upper()
            if executor_envelope
            else "SKIPPED"
        )
        if executor_status != "EXECUTED":
            skip_message = (
                f"Execution skipped (status={executor_status}); "
                f"no command was run on the host. {exec_summary}"
            )
            self._audit.append_stage(
                STAGE_EXECUTION_SKIPPED,
                request_id,
                actor=self._actor,
                instruction=instruction,
                candidate_commands=candidate_commands,
                validator=validator_envelope,
                executor=executor_envelope,
                reason=skip_message,
            )
            trail.append(
                self._trail_entry(
                    "execution_skipped",
                    status="SKIPPED",
                    message=skip_message,
                    payload={
                        "executorStatus": executor_status,
                        "decision": decision,
                    },
                )
            )

        # ===== Step 6: final_answer_generated =====
        final_answer = self._generate_answer(
            instruction=instruction,
            intent=intent,
            mcp_trace=mcp_trace,
            validator_envelope=validator_envelope,
            executor_envelope=executor_envelope,
            danger_category=danger_category,
        )
        trail.append(
            self._trail_entry(
                "final_answer_generated",
                status="OK",
                message=f"answer length={len(final_answer)} chars",
            )
        )

        # ===== Final audit event with full trail =====
        self._audit.append_stage(
            STAGE_COMPLETED,
            request_id,
            actor=self._actor,
            instruction=instruction,
            candidate_commands=candidate_commands,
            validator=validator_envelope,
            executor=executor_envelope,
            metadata={
                "intent": intent.intent_id,
                "dangerCategory": danger_category,
                "mcpToolCount": len(mcp_trace),
                "mcpFailures": sum(1 for t in mcp_trace if not t["success"]),
                "promptInjection": injection_envelope,
                "configGuard": config_guard_envelope,
                "finalAnswer": final_answer,
                "trail": trail,
            },
        )

        return {
            "requestId": request_id,
            "instruction": instruction,
            "intent": intent.intent_id,
            "intentLabel": intent.intent_label,
            "riskLevel": risk_level,
            "decision": decision,
            "dangerCategory": danger_category,
            "plan": plan,
            "mcpTrace": mcp_trace,
            "promptInjection": injection_envelope,
            "configGuard": config_guard_envelope,
            "safetyValidation": validator_envelope,
            "executionResult": executor_envelope,
            "auditTrail": trail,
            "finalAnswer": final_answer,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _collect_mcp_context(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Dispatch every planned MCP tool call and capture the envelope."""
        out: list[dict[str, Any]] = []
        for spec in tools:
            tool_name = str(spec.get("tool", ""))
            params = dict(spec.get("params", {}) or {})
            method = getattr(self._os, tool_name, None)
            if method is None or not callable(method):
                out.append(
                    {
                        "server": "os-mcp-server",
                        "tool": tool_name,
                        "success": False,
                        "summary": f"client has no method '{tool_name}'",
                        "result": None,
                        "error": "tool_not_found",
                    }
                )
                continue
            try:
                envelope = await method(**params)
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "OS MCP tool %s raised", tool_name, exc_info=exc
                )
                envelope = {
                    "server": "os-mcp-server",
                    "tool": tool_name,
                    "success": False,
                    "summary": f"tool raised: {exc.__class__.__name__}",
                    "result": None,
                    "error": "client_error",
                }
            # Normalize the envelope shape so callers always see the
            # same keys regardless of which client / version produced it.
            out.append(
                {
                    "server": str(envelope.get("server", "os-mcp-server")),
                    "tool": str(envelope.get("tool", tool_name)),
                    "success": bool(envelope.get("success")),
                    "summary": str(envelope.get("summary", "")),
                    "result": envelope.get("result"),
                    "error": envelope.get("error"),
                }
            )
        return out

    def _maybe_execute(
        self,
        *,
        intent: IntentMatch,
        instruction: str,
        candidate_commands: list[str],
        validator_envelope: dict[str, Any],
        is_dangerous_intent: bool,
    ) -> tuple[dict[str, Any] | None, str]:
        """Run the first candidate command iff validator==ALLOW.

        For non-ALLOW paths we still return a *synthetic* executor
        envelope (status=BLOCKED / PENDING_APPROVAL / SKIPPED) so the
        UI / audit log can render a consistent ``executionResult``
        card without the caller having to special-case nullability.
        """
        decision = validator_envelope.get("decision")
        first_command = candidate_commands[0] if candidate_commands else ""

        if decision == DECISION_BLOCK:
            envelope = self._build_skipped_envelope(
                status="BLOCKED",
                command=first_command,
                reason=(
                    "Blocked by intent validator before execution. "
                    f"Reason: {validator_envelope.get('reason', 'matched BLOCK rule')}"
                ),
                validator=validator_envelope,
            )
            return envelope, "skipped: BLOCKED by safety validator"

        if decision == DECISION_REQUIRE_APPROVAL:
            envelope = self._build_skipped_envelope(
                status="PENDING_APPROVAL",
                command=first_command,
                reason=(
                    "Awaiting human approval. "
                    f"Reason: {validator_envelope.get('reason', 'matched approval rule')}"
                ),
                validator=validator_envelope,
            )
            return envelope, "skipped: REQUIRE_APPROVAL - awaiting human"

        if decision != DECISION_ALLOW:
            envelope = self._build_skipped_envelope(
                status="SKIPPED",
                command=first_command,
                reason=f"Unknown validator decision '{decision}'",
                validator=validator_envelope,
            )
            return envelope, f"skipped: unknown validator decision '{decision}'"

        # decision == ALLOW from here on.

        if is_dangerous_intent:
            # Defensive belt-and-suspenders: even if the validator somehow
            # ALLOWed a request the parser flagged as dangerous, refuse to
            # execute and surface it as BLOCKED to the audit trail.
            envelope = self._build_skipped_envelope(
                status="BLOCKED",
                command=first_command,
                reason=(
                    "Refusing to execute a request that was classified as "
                    "DANGEROUS_COMMAND, regardless of validator output."
                ),
                validator=validator_envelope,
            )
            return envelope, "skipped: dangerous intent overrides ALLOW"

        if not self._executor_enabled:
            envelope = self._build_skipped_envelope(
                status="SKIPPED",
                command=first_command,
                reason="Executor disabled by configuration",
                validator=validator_envelope,
            )
            return envelope, "skipped: executor disabled by configuration"
        if not candidate_commands:
            envelope = self._build_skipped_envelope(
                status="SKIPPED",
                command="",
                reason="ALLOW with empty candidate list - nothing to run",
                validator=validator_envelope,
            )
            return envelope, "skipped: no candidate command in plan"

        cmd = candidate_commands[0]
        envelope = self._executor.execute(
            cmd,
            instruction=instruction,
            validator_override=validator_envelope,
        )
        status = envelope.get("status", "?")
        exit_code = envelope.get("exitCode")
        return envelope, (
            f"executed: command='{cmd}' status={status} exitCode={exit_code}"
        )

    def _short_circuit(
        self,
        *,
        request_id: str,
        instruction: str,
        trail: list[dict[str, Any]],
        injection_envelope: dict[str, Any],
        config_guard_envelope: dict[str, Any],
        intent: IntentMatch | None = None,
        candidate_commands: list[str] | None = None,
        source: str,
    ) -> dict[str, Any]:
        """Produce a complete response envelope for an early-blocked request.

        Called when either the prompt-injection guard or the system-config
        guard refuses the request before the intent-validator pipeline.
        Builds synthetic ``safetyValidation`` and ``executionResult``
        envelopes so the frontend sees a consistent four-card layout
        (injection / config / validator / execution) regardless of which
        guard fired.
        """
        cmds = candidate_commands or []
        first_command = cmds[0] if cmds else ""
        is_injection = source == "prompt_injection"
        guard_envelope = injection_envelope if is_injection else config_guard_envelope
        guard_risk = str(guard_envelope.get("riskLevel", "HIGH"))
        guard_reason_zh = str(
            guard_envelope.get("reasonZh") or guard_envelope.get("reason") or ""
        )
        guard_label = (
            "反提示词注入护栏" if is_injection else "关键配置文件确定性护栏"
        )

        synthetic_validator = {
            "decision": DECISION_BLOCK,
            "riskLevel": guard_risk,
            "matchedRules": [],
            "reason": guard_envelope.get("reason", f"{source} guard blocked the request."),
            "safeAlternative": None,
            "source": source,
        }
        synthetic_executor = self._build_skipped_envelope(
            status="BLOCKED",
            command=first_command,
            reason=guard_envelope.get("reason", f"{source} guard blocked the request."),
            validator=synthetic_validator,
        )

        # Audit: emit a final completed event so the JSONL stays consistent.
        final_answer = (
            f"[BLOCKED · {guard_label}] {guard_reason_zh} "
            "已立即终止流程，未触达 MCP 与执行器。"
        )
        trail.append(
            self._trail_entry(
                "final_answer_generated",
                status="OK",
                message=f"answer length={len(final_answer)} chars",
            )
        )
        self._audit.append_stage(
            STAGE_COMPLETED,
            request_id,
            actor=self._actor,
            instruction=instruction,
            candidate_commands=cmds,
            validator=synthetic_validator,
            executor=synthetic_executor,
            metadata={
                "intent": (intent.intent_id if intent else None),
                "shortCircuit": source,
                "promptInjection": injection_envelope,
                "configGuard": config_guard_envelope,
                "finalAnswer": final_answer,
                "trail": trail,
            },
        )

        plan = intent.to_dict() if intent else {
            "intent": "BLOCKED_BY_GUARD",
            "intentLabel": guard_label,
            "candidateCommands": [],
            "extractedParams": {},
            "mcpTools": [],
        }
        return {
            "requestId": request_id,
            "instruction": instruction,
            "intent": (intent.intent_id if intent else "BLOCKED_BY_GUARD"),
            "intentLabel": (intent.intent_label if intent else guard_label),
            "riskLevel": guard_risk,
            "decision": DECISION_BLOCK,
            "dangerCategory": source,
            "plan": plan,
            "mcpTrace": [],
            "promptInjection": injection_envelope,
            "configGuard": config_guard_envelope,
            "safetyValidation": synthetic_validator,
            "executionResult": synthetic_executor,
            "auditTrail": trail,
            "finalAnswer": final_answer,
        }

    @staticmethod
    def _build_skipped_envelope(
        *,
        status: str,
        command: str,
        reason: str,
        validator: dict[str, Any],
    ) -> dict[str, Any]:
        """Construct a synthetic executor envelope for a non-EXECUTED path.

        Mirrors the shape returned by ``LeastPrivilegeExecutor.execute``
        so downstream consumers (UI, audit log) see the same keys.
        """
        return {
            "status": status,
            "command": command,
            "argv": [],
            "executedAs": "ops-agent",
            "exitCode": None,
            "stdout": "",
            "stderr": "",
            "startedAt": None,
            "endedAt": None,
            "durationMs": 0,
            "timeoutSeconds": 5,
            "reason": reason,
            "commandId": None,
            "validator": validator,
        }

    def _generate_answer(
        self,
        *,
        instruction: str,
        intent: IntentMatch,
        mcp_trace: list[dict[str, Any]],
        validator_envelope: dict[str, Any],
        executor_envelope: dict[str, Any] | None,
        danger_category: str | None,
    ) -> str:
        """Build a deterministic, template-based final answer.

        We intentionally avoid the LLM here so the OPS endpoint can run
        offline and so unit tests are stable. A future phase can wrap
        this method with an LLM-powered summarizer if desired.
        """
        decision = validator_envelope.get("decision")
        risk = validator_envelope.get("riskLevel", "?")
        reason = str(validator_envelope.get("reason", "")).strip()
        safe_alt = validator_envelope.get("safeAlternative")

        if decision == DECISION_BLOCK:
            cat = f"category={danger_category}; " if danger_category else ""
            return (
                f"[BLOCKED · risk={risk}] 该指令已被安全策略拦截，"
                f"未在主机上执行任何命令。{cat}原因：{reason or '匹配 BLOCK 规则'}。"
                f" 建议替代方案：{safe_alt or 'n/a'}。"
            )
        if decision == DECISION_REQUIRE_APPROVAL:
            return (
                f"[PENDING APPROVAL · risk={risk}] 该指令需人工审批，未自动执行。"
                f"原因：{reason or '匹配 REQUIRE_APPROVAL 规则'}。"
                f" 建议下一步：{safe_alt or 'await operator'}。"
            )

        # ALLOW path
        if intent.intent_id == INTENT_UNKNOWN:
            return (
                "[UNKNOWN INTENT] Could not parse the instruction into a "
                "known OPS intent. Please rephrase, e.g. 'show disk usage' "
                "or 'check what process uses port 8080'."
            )

        successes = [t for t in mcp_trace if t["success"]]
        failures = [t for t in mcp_trace if not t["success"]]

        if intent.intent_id == INTENT_RAW_COMMAND:
            head = "[ALLOW · raw command] Command passed safety validator."
        else:
            head = f"[{intent.intent_label}] "
            if successes:
                summaries = "; ".join(t["summary"] for t in successes[:3])
                head += summaries
            else:
                head += "no MCP context available on this host"

        tail_parts: list[str] = []
        if executor_envelope and executor_envelope.get("status") == "EXECUTED":
            tail_parts.append(
                f"Verified via '{executor_envelope.get('command')}' "
                f"(exit={executor_envelope.get('exitCode')})"
            )
        elif executor_envelope is not None:
            tail_parts.append(
                f"Executor status: {executor_envelope.get('status')}"
            )
        if failures:
            tail_parts.append(
                f"{len(failures)} MCP tool(s) unavailable on host"
            )
        if tail_parts:
            head += ". " + "; ".join(tail_parts) + "."
        elif not head.endswith("."):
            head += "."
        return head

    @staticmethod
    def _trail_entry(
        step: str,
        *,
        status: str = "OK",
        message: str = "",
        payload: dict[str, Any] | None = None,
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Build one entry of the in-memory ``auditTrail`` list.

        Schema matches the frontend contract:
        ``{step, status, message, timestamp}``. ``summary`` is preserved
        as an alias of ``message`` for backwards compatibility with the
        original audit trail consumers.
        """
        text = message or summary or ""
        entry: dict[str, Any] = {
            "step": step,
            "status": status,
            "message": text,
            "summary": text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if payload:
            entry["payload"] = payload
        return entry


__all__ = ["OpsOrchestrator"]
