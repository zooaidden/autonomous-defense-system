from .llm import LLMClient, MockLLMClient, HttpChatCompletionLLMClient, create_default_llm_client

__all__ = [
    "LLMClient",
    "MockLLMClient",
    "HttpChatCompletionLLMClient",
    "create_default_llm_client",
    "DebateOrchestrator",
    "OpsOrchestrator",
]


# Lazy re-export to avoid the circular import:
#   services.__init__ -> orchestrator -> workflows.debate_workflow -> agents
#       -> agents.coordinator -> services.llm  (back to services.__init__)
# DebateOrchestrator is heavy and only needed by callers that explicitly ask
# for it; pulling it eagerly forces ``orchestrator`` to load before
# ``agents`` has finished initializing, which then fails to find
# ``CoordinatorAgent``.
#
# OpsOrchestrator is lazy-loaded for the same reason: it pulls in the
# safety / executor / audit packages, none of which need to be imported
# at module-init time for callers that only use the debate workflow.
def __getattr__(name):
    if name == "DebateOrchestrator":
        from .orchestrator import DebateOrchestrator

        return DebateOrchestrator
    if name == "OpsOrchestrator":
        from .ops_orchestrator import OpsOrchestrator

        return OpsOrchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
