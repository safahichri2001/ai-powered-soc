from typing import Any

from agent.llm.ollama_client import OllamaClient
from agent.prompts.security_analysis import build_security_analysis_prompt
from agent.security.input_guard import InputGuard
from agent.security.semantic_guard import SemanticGuard
from rag.retrieval.context_builder import build_context
from rag.retrieval.retriever import Retriever


class RAGPipeline:
    """Secure RAG pipeline with lexical and semantic input protection."""

    def __init__(
        self,
        retriever: Retriever,
        llm: OllamaClient | None = None,
        input_guard: InputGuard | None = None,
        semantic_guard: SemanticGuard | None = None,
    ) -> None:
        self.retriever = retriever
        self.llm = llm or OllamaClient()
        self.input_guard = input_guard or InputGuard()
        self.semantic_guard = semantic_guard or SemanticGuard()

    def analyze(
        self,
        query: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """Run security checks before retrieval and LLM generation."""

        # Layer 1: fast rule-based detection.
        input_result = self.input_guard.assess(query)

        if input_result.decision == "BLOCK":
            return {
                "query": query,
                "guard_decision": "BLOCK",
                "guard_layer": "input_guard",
                "guard_risk_score": input_result.risk_score,
                "guard_reason": input_result.reason,
                "input_guard_decision": input_result.decision,
                "semantic_guard_decision": "NOT_RUN",
                "semantic_guard_risk_score": None,
                "semantic_guard_reason": None,
                "retrieved_results": [],
                "context": "",
                "response": (
                    "Request blocked by the security layer because "
                    "a potential prompt injection was detected."
                ),
            }

        # Layer 2: semantic detection.
        semantic_result = self.semantic_guard.assess(query)

        if semantic_result.decision == "BLOCK":
            return {
                "query": query,
                "guard_decision": "BLOCK",
                "guard_layer": "semantic_guard",
                "guard_risk_score": semantic_result.risk_score,
                "guard_reason": semantic_result.reason,
                "input_guard_decision": input_result.decision,
                "semantic_guard_decision": semantic_result.decision,
                "semantic_guard_risk_score": semantic_result.risk_score,
                "semantic_guard_reason": semantic_result.reason,
                "retrieved_results": [],
                "context": "",
                "response": (
                    "Request blocked by the semantic security layer "
                    "because it is semantically similar to known "
                    "prompt-injection attacks."
                ),
            }

        # Layer 3: normal RAG pipeline.
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
            "guard_decision": "ALLOW",
            "guard_layer": "none",
            "guard_risk_score": 0.0,
            "guard_reason": "security_checks_passed",
            "input_guard_decision": input_result.decision,
            "semantic_guard_decision": semantic_result.decision,
            "semantic_guard_risk_score": semantic_result.risk_score,
            "semantic_guard_reason": semantic_result.reason,
            "retrieved_results": results,
            "context": context,
            "response": response,
        }