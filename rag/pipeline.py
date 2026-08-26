from typing import Any

from agent.llm.ollama_client import OllamaClient
from agent.prompts.security_analysis import build_security_analysis_prompt
from agent.security.input_guard import InputGuard
from rag.retrieval.context_builder import build_context
from rag.retrieval.retriever import Retriever


class RAGPipeline:
    """Secure RAG pipeline with input validation before retrieval and generation."""

    def __init__(
        self,
        retriever: Retriever,
        llm: OllamaClient | None = None,
        input_guard: InputGuard | None = None,
    ) -> None:
        self.retriever = retriever
        self.llm = llm or OllamaClient()
        self.input_guard = input_guard or InputGuard()

    def analyze(
        self,
        query: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """Assess the input, then run retrieval and LLM generation if allowed."""

        guard_result = self.input_guard.assess(query)

        if guard_result.decision == "BLOCK":
            return {
                "query": query,
                "guard_decision": guard_result.decision,
                "guard_risk_score": guard_result.risk_score,
                "guard_reason": guard_result.reason,
                "retrieved_results": [],
                "context": "",
                "response": (
                    "Request blocked by the security layer because "
                    "a potential prompt injection was detected."
                ),
            }

        results = self.retriever.search(
            query=query,
            top_k=top_k,
        )

        context = build_context(results)

        prompt = build_security_analysis_prompt(
            query=query,
            context=context,
        )

        response = self.llm.generate(prompt)

        return {
            "query": query,
            "guard_decision": guard_result.decision,
            "guard_risk_score": guard_result.risk_score,
            "guard_reason": guard_result.reason,
            "retrieved_results": results,
            "context": context,
            "response": response,
        }