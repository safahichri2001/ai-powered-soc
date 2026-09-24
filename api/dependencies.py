from __future__ import annotations

import threading

from agent.analysis.alert_status_store import AlertStatusStore
from agent.analysis.live_alert_investigator import (
    LiveAlertInvestigator,
    build_alert_analysis_pipeline,
)
from agent.security.tool_misuse_guard import ToolMisuseGuard
from agent.tools.executor import ToolExecutor
from agent.tools.soc_tools import build_default_registry
from rag.retrieval.retriever import Retriever
from rag.retrieval.vector_store import build_vector_store

_investigator: LiveAlertInvestigator | None = None
_investigator_lock = threading.Lock()


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

    Uses an explicit lock rather than @lru_cache: FastAPI runs each
    dependency call in a threadpool, so two requests arriving before
    the (multi-second) first build finishes would otherwise both
    try to open the local Qdrant store at once -- it only allows one
    process/thread in at a time and the second attempt raises. The
    lock makes the second caller wait for the first build instead of
    racing it.
    """

    global _investigator

    if _investigator is None:
        with _investigator_lock:
            if _investigator is None:
                retriever = Retriever(vector_store=build_vector_store())
                rag_pipeline = build_alert_analysis_pipeline(retriever=retriever)

                registry = build_default_registry()
                tool_executor = ToolExecutor(
                    registry=registry, guard=ToolMisuseGuard()
                )

                _investigator = LiveAlertInvestigator(
                    rag_pipeline=rag_pipeline,
                    tool_executor=tool_executor,
                )

    return _investigator


def get_tool_executor() -> ToolExecutor:
    """
    The same ToolExecutor the investigator uses for enrichment --
    reused here (not a second, independently-constructed one) so an
    approved SOAR action goes through the identical guard instance
    and audit log as everything else.
    """

    return get_investigator().tool_executor


_alert_status_store = AlertStatusStore()


def get_alert_status_store() -> AlertStatusStore:
    """
    Construction is cheap (just a path and a lock, no I/O until a
    method is called), so unlike get_investigator() this needs no
    lazy double-checked locking -- a single module-level instance is
    enough.
    """

    return _alert_status_store
