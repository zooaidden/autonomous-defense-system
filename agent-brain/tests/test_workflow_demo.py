from agent_brain.main import _build_mock_event
from agent_brain.services import DebateOrchestrator, MockLLMClient


def test_workflow_generates_strategy():
    orchestrator = DebateOrchestrator(llm=MockLLMClient())
    result = orchestrator.process_event(_build_mock_event())
    assert result["finalStrategy"]["strategyId"]
    assert result["debateState"]["status"] == "CLOSED"
    # The mock demo event is HIGH severity with riskScore=0.89, which under the
    # Phase 5 human-approval boundary forces the strategy out of the auto-exec
    # path. We therefore no longer assert ``approved=True``; instead we assert
    # the demo runs end-to-end and produces a Coordinator decision.
    cd = result["coordinatorDecision"]
    assert cd["status"] in {
        "approved_for_execution",
        "requires_approval",
        "needs_revision",
    }
    # auto_execution_allowed and human_approval_required must be consistent
    if cd["auto_execution_allowed"]:
        assert cd["human_approval_required"] is False
        assert result["finalStrategy"]["approved"] is True
    else:
        assert cd["human_approval_required"] is True
        assert result["finalStrategy"]["approved"] is False

