from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from agent_brain.agents import CoordinatorAgent, PlannerAgent, PlannerRevisionAgent, RedTeamerAgent
from agent_brain.integrations.policy_client import PolicyMCPClient
from agent_brain.models import DebateState, NextAction
from agent_brain.services.llm import LLMClient


class WorkflowState(TypedDict):
    debate_state: DebateState


class DebateWorkflow:
    def __init__(
        self,
        llm: LLMClient,
        *,
        policy_client: PolicyMCPClient | None = None,
    ) -> None:
        # ``policy_client`` is optional so existing tests keep working;
        # when provided it is forwarded to the Coordinator for the final
        # policy gate before approving execution.
        self.planner = PlannerAgent(llm)
        self.red_teamer = RedTeamerAgent(llm)
        self.revision = PlannerRevisionAgent(llm)
        self.coordinator = CoordinatorAgent(llm, policy_client=policy_client)
        self.graph = self._build_graph()

    def _build_graph(self):
        graph_builder = StateGraph(WorkflowState)
        graph_builder.add_node("planner", self._planner_node)
        graph_builder.add_node("red_teamer", self._red_teamer_node)
        graph_builder.add_node("revision", self._revision_node)
        graph_builder.add_node("coordinator", self._coordinator_node)

        graph_builder.add_edge(START, "planner")
        graph_builder.add_edge("planner", "red_teamer")
        graph_builder.add_edge("red_teamer", "revision")
        graph_builder.add_edge("revision", "coordinator")
        graph_builder.add_conditional_edges(
            "coordinator",
            self._coordinator_router,
            {
                "continue": "red_teamer",
                "finish": END,
            },
        )
        return graph_builder.compile()

    def run(self, state: DebateState) -> DebateState:
        result = self.graph.invoke({"debate_state": state})
        return result["debate_state"]

    # ------------------------------------------------------------------
    # Agent nodes (each appends an audit turn after running)
    # ------------------------------------------------------------------

    def _planner_node(self, state: WorkflowState) -> WorkflowState:
        debate_state = self.planner.run(state["debate_state"])
        self._append_audit_turn(debate_state, "Planner", self._summarize_planner(debate_state))
        return {"debate_state": debate_state}

    def _red_teamer_node(self, state: WorkflowState) -> WorkflowState:
        debate_state = self.red_teamer.run(state["debate_state"])
        self._append_audit_turn(debate_state, "RedTeamer", self._summarize_red_teamer(debate_state))
        return {"debate_state": debate_state}

    def _revision_node(self, state: WorkflowState) -> WorkflowState:
        debate_state = self.revision.run(state["debate_state"])
        self._append_audit_turn(debate_state, "Revision", self._summarize_revision(debate_state))
        return {"debate_state": debate_state}

    def _coordinator_node(self, state: WorkflowState) -> WorkflowState:
        debate_state = self.coordinator.run(state["debate_state"])
        self._append_audit_turn(debate_state, "Coordinator", self._summarize_coordinator(debate_state))
        return {"debate_state": debate_state}

    # ------------------------------------------------------------------
    # Audit turn helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append_audit_turn(debate_state: DebateState, agent: str, summary: dict) -> None:
        debate_state.audit_turns.append({
            "agent": agent,
            "round": debate_state.round,
            "timestamp": datetime.now(UTC).isoformat(),
            "input_event_id": debate_state.securityEvent.eventId,
            "summary": summary,
        })

    @staticmethod
    def _summarize_planner(ds: DebateState) -> dict:
        proposal = ds.plannerProposal
        return {
            "has_proposal": proposal is not None,
            "threat_type": proposal.threatType if proposal else None,
            "target_layer": proposal.targetLayer if proposal else None,
            "action_count": len(proposal.actions) if proposal else 0,
            "confidence": proposal.confidence if proposal else None,
            "topology_summary": (
                getattr(ds.plannerMetadata, "topology_summary", "")
                if ds.plannerMetadata
                else None
            ),
        }

    @staticmethod
    def _summarize_red_teamer(ds: DebateState) -> dict:
        findings = ds.redTeamFindings
        return {
            "challenge_count": len(ds.redTeamChallenges),
            "topology_finding_count": len(findings.topology_based_findings) if findings else 0,
            "residual_attack_path_count": len(findings.residual_attack_paths) if findings else 0,
            "business_impact_risk_count": len(findings.business_impact_risks) if findings else 0,
            "mcp_error": findings.mcp_error if findings else None,
        }

    @staticmethod
    def _summarize_revision(ds: DebateState) -> dict:
        revised = ds.revisedProposal
        original = ds.plannerProposal
        return {
            "has_revision": revised is not None,
            "action_count_before": len(original.actions) if original else 0,
            "action_count_after": len(revised.actions) if revised else 0,
            "confidence_before": original.confidence if original else None,
            "confidence_after": revised.confidence if revised else None,
            "unresolved_count": len(ds.unresolvedChallenges),
        }

    @staticmethod
    def _summarize_coordinator(ds: DebateState) -> dict:
        fd = ds.finalDecision
        return {
            "decision": fd.decision.value if fd else None,
            "next_action": fd.nextAction.value if fd else None,
            "approved": fd.decision == "APPROVE" if fd else False,
            "human_approval_required": fd.humanApprovalRequired if fd else None,
            "auto_execution_allowed": fd.autoExecutionAllowed if fd else None,
            "rationale_preview": (
                fd.rationale[:200] if fd and fd.rationale else None
            ),
        }

    def _coordinator_router(self, state: WorkflowState) -> str:
        decision = state["debate_state"].finalDecision
        if decision and decision.nextAction == NextAction.CONTINUE_DEBATE:
            return "continue"
        return "finish"

