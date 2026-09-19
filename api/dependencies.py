from __future__ import annotations

from functools import lru_cache

from agent.analysis.live_alert_investigator import (
    LiveAlertInvestigator,
    build_alert_analysis_pipeline,
)
from agent.security.tool_misuse_guard import ToolMisuseGuard
from agent.tools.executor import ToolExecutor
from agent.tools.soc_tools import build_default_registry
from rag.retrieval.retriever import Retriever


@lru_cache(maxsize=1)
def get_investigator() -> LiveAlertInvestigator:
    """
    Build the single LiveAlertInvestigator the API serves requests
    from, cached so every request reuses the same watermark state
    and the same ToolExecutor/guard instance.

    Construction never calls Wazuh, Ollama, or any network service
    -- Retriever/EmbeddingModel only touch the local embedding model
    and the local Qdrant store, and build_default_registry() defers
    all Wazuh calls to when a tool actually runs (see its own
    docstring). So this is safe to call even when the lab VMs are
    offline; failures surface per-request instead of at startup.
    """

    retriever = Retriever()
    rag_pipeline = build_alert_analysis_pipeline(retriever=retriever)

    registry = build_default_registry()
    tool_executor = ToolExecutor(registry=registry, guard=ToolMisuseGuard())

    return LiveAlertInvestigator(
        rag_pipeline=rag_pipeline,
        tool_executor=tool_executor,
    )


def get_tool_executor() -> ToolExecutor:
    """
    The same ToolExecutor the investigator uses for enrichment --
    reused here (not a second, independently-constructed one) so an
    approved SOAR action goes through the identical guard instance
    and audit log as everything else.
    """

    return get_investigator().tool_executor
