"""Map legacy MVP HTTP contracts (acd-backend / agent-service) onto agent-brain DebateWorkflow."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from agent_brain.models import (
    DebateState,
    DefenseStrategy,
    FinalDecision,
    NextAction,
    SecurityEvent,
    Severity,
)
from agent_brain.workflows.debate_workflow import DebateWorkflow


class MvpSecurityEvent(BaseModel):
    """Matches Java ``com.acd.defense.domain.SecurityEvent`` (legacy MVP API)."""

    model_config = {"extra": "ignore"}

    eventId: str | None = None
    source: str
    eventType: str
    severity: str = "MEDIUM"
    timestamp: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


def _parse_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.MEDIUM
    try:
        return Severity(raw.upper())
    except ValueError:
        return Severity.MEDIUM


def mvp_event_to_brain(mvp: MvpSecurityEvent) -> SecurityEvent:
    attrs = dict(mvp.attributes or {})
    subject = attrs.get("subject") or mvp.eventType or "unknown/subject"
    action = attrs.get("action") or mvp.eventType
    obj = attrs.get("object") or ""
    ctx = {
        **attrs,
        "mvpEventType": mvp.eventType,
        "mvpSource": mvp.source,
    }
    return SecurityEvent(
        eventId=mvp.eventId or str(uuid4()),
        timestamp=mvp.timestamp or datetime.now(UTC),
        sourceType=mvp.source,
        subject=str(subject),
        action=str(action),
        object=str(obj),
        context=ctx,
        severity=_parse_severity(mvp.severity),
        riskScore=float(attrs.get("riskScore", 0.72)),
        labels=list(attrs["labels"]) if isinstance(attrs.get("labels"), list) else [],
    )


def _risk_level_to_mvp_risk_string(decision: FinalDecision | None, strategy: DefenseStrategy) -> str:
    if decision is not None:
        return decision.riskLevel.value.upper()
    if strategy.confidence >= 0.85:
        return "HIGH"
    if strategy.confidence >= 0.6:
        return "MEDIUM"
    return "LOW"


def brain_strategy_to_mvp(strategy: DefenseStrategy, decision: FinalDecision | None) -> dict[str, Any]:
    actions = [f"{a.type.value}:{a.target}" for a in strategy.actions]
    return {
        "strategyId": strategy.strategyId,
        "strategyType": f"{strategy.threatType.value}_{strategy.targetLayer.value}",
        "actions": actions,
        "rationale": strategy.rationale,
        "riskLevel": _risk_level_to_mvp_risk_string(decision, strategy),
    }


def _planner_ideas_from_state(ds: DebateState) -> list[str]:
    p = ds.plannerProposal
    if not p:
        return []
    lines = [p.rationale]
    lines.extend(f"{a.type.value}:{a.target}" for a in p.actions[:12])
    return [x for x in lines if x]


def _red_challenges_lines(ds: DebateState) -> list[str]:
    return [f"{c.title}: {c.description}" for c in ds.redTeamChallenges]


def brain_state_to_mvp_debate_state(ds: DebateState) -> dict[str, Any]:
    fd = ds.finalDecision
    coord: dict[str, Any]
    if fd:
        coord = fd.model_dump(mode="json")
    else:
        coord = {"selected": "pending", "note": "Coordinator decision not finalized"}
    coord.setdefault("agentBrainDebateId", ds.debateId)
    coord.setdefault("round", ds.round)
    coord.setdefault("history", [t.model_dump(mode="json") for t in ds.history[-32:]])
    return {
        "roundId": ds.debateId,
        "plannerIdeas": _planner_ideas_from_state(ds),
        "redTeamChallenges": _red_challenges_lines(ds),
        "coordinatorDecision": coord,
    }


def pick_final_strategy(ds: DebateState) -> DefenseStrategy:
    strat = ds.revisedProposal or ds.plannerProposal
    if strat is None:
        raise RuntimeError("Debate finished without a DefenseStrategy")
    return strat


def build_mvp_debate_response(final_state: DebateState) -> dict[str, Any]:
    strategy = pick_final_strategy(final_state)
    return {
        "debateState": brain_state_to_mvp_debate_state(final_state),
        "strategy": brain_strategy_to_mvp(strategy, final_state.finalDecision),
    }


def initial_debate_state(event: SecurityEvent) -> DebateState:
    return DebateState(
        debateId=f"deb-{uuid4()}",
        securityEvent=event,
        retrievedContext=["baseline policy set", "recent incident summary"],
        round=0,
    )


def run_mvp_debate_sync(workflow: DebateWorkflow, mvp: MvpSecurityEvent) -> dict[str, Any]:
    brain_event = mvp_event_to_brain(mvp)
    state = initial_debate_state(brain_event)
    final_state = workflow.run(state)
    return build_mvp_debate_response(final_state)


def _agent_output_preview(ds: DebateState, agent: str) -> Any:
    if agent == "planner":
        return _planner_ideas_from_state(ds)
    if agent == "red_teamer":
        return _red_challenges_lines(ds)
    if agent == "revision":
        rp = ds.revisedProposal
        return rp.rationale if rp else ""
    if agent == "coordinator":
        st = pick_final_strategy(ds)
        return brain_strategy_to_mvp(st, ds.finalDecision)
    return {}


def run_mvp_debate_stream(workflow: DebateWorkflow, mvp: MvpSecurityEvent) -> Iterator[dict[str, Any]]:
    """SSE payloads compatible with ``agent-service`` / ``DefenseStreamController``."""

    brain_event = mvp_event_to_brain(mvp)
    ds = initial_debate_state(brain_event)
    round_id = ds.debateId

    yield {
        "type": "debate_start",
        "roundId": round_id,
        "maxRounds": ds.maxRounds,
        "llmEnabled": True,
        "model": "agent-brain",
    }

    macro = 0
    max_macros = max(ds.maxRounds * 3, 8)

    while macro < max_macros:
        macro += 1
        yield {"type": "round_start", "round": macro}

        if macro == 1:
            sequence = (
                ("planner", workflow.planner.run),
                ("red_teamer", workflow.red_teamer.run),
                ("revision", workflow.revision.run),
                ("coordinator", workflow.coordinator.run),
            )
        else:
            sequence = (
                ("red_teamer", workflow.red_teamer.run),
                ("revision", workflow.revision.run),
                ("coordinator", workflow.coordinator.run),
            )

        for agent_name, runner in sequence:
            yield {"type": "agent_start", "round": macro, "agent": agent_name}
            try:
                ds = runner(ds)
                yield {
                    "type": "agent_done",
                    "round": macro,
                    "agent": agent_name,
                    "output": _agent_output_preview(ds, agent_name),
                }
            except Exception as e:  # noqa: BLE001
                yield {"type": "agent_error", "round": macro, "agent": agent_name, "error": str(e)}
                return

        fd = ds.finalDecision
        need_continue = bool(fd and fd.nextAction == NextAction.CONTINUE_DEBATE)
        strat_snap = ds.revisedProposal or ds.plannerProposal
        yield {
            "type": "round_end",
            "round": macro,
            "needAnotherRound": need_continue,
            "confidence": strat_snap.confidence if strat_snap else None,
        }

        if not need_continue:
            break

    try:
        strategy = pick_final_strategy(ds)
    except RuntimeError as err:
        yield {"type": "fatal_error", "error": str(err)}
        return

    debate_state = brain_state_to_mvp_debate_state(ds)
    strat_payload = brain_strategy_to_mvp(strategy, ds.finalDecision)

    yield {"type": "debate_done", "debateState": debate_state, "strategy": strat_payload}


def sse_lines_from_stream(events: Iterator[dict[str, Any]]) -> Iterator[str]:
    for evt in events:
        yield f"data: {json.dumps(evt, ensure_ascii=False, default=str)}\n\n"
