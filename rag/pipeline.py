from typing import Any

from agent.llm.ollama_client import OllamaClient
from agent.security.input_guard import InputGuard
from agent.security.rag_context_guard import RAGContextGuard
from agent.security.semantic_guard import SemanticGuard
from agent.prompts.security_analysis import build_security_analysis_prompt
from rag.retrieval.context_builder import build_context
from rag.retrieval.retriever import Retriever


class RAGPipeline:
    """Secure RAG pipeline with input and context protection."""

    def __init__(
        self,
        retriever: Retriever,
        llm: OllamaClient | None = None,
        input_guard: InputGuard | None = None,
        semantic_guard: SemanticGuard | None = None,
        rag_context_guard: RAGContextGuard | None = None,
    ) -> None:
        self.retriever = retriever
        self.llm = llm or OllamaClient()

        self.input_guard = (
            input_guard or InputGuard()
        )

        self.semantic_guard = (
            semantic_guard or SemanticGuard()
        )

        self.rag_context_guard = (
            rag_context_guard
            or RAGContextGuard(
                threshold=0.56,
            )
        )

    def _build_context_text(
        self,
        results: list[dict[str, Any]],
    ) -> str:
        """Extract retrieved content into one context string."""

        return "\n\n".join(
            str(result.get("content", ""))
            for result in results
            if result.get("content")
        )

    def analyze(
        self,
        query: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """Run the secured RAG analysis pipeline."""

        # -----------------------------------------------------
        # Layer 1: input guard
        # -----------------------------------------------------

        input_result = self.input_guard.assess(
            query
        )

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
                "rag_context_guard_decision": "NOT_RUN",
                "rag_context_guard_risk_score": None,
                "rag_context_guard_reason": None,
                "rag_context_guard_matched_attack": None,
                "rag_context_guard_matched_segment": None,
                "retrieved_results": [],
                "context": "",
                "response": (
                    "Request blocked by the input security layer."
                ),
            }

        # -----------------------------------------------------
        # Layer 2: semantic input guard
        # -----------------------------------------------------

        semantic_result = self.semantic_guard.assess(
            query
        )

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
                "rag_context_guard_decision": "NOT_RUN",
                "rag_context_guard_risk_score": None,
                "rag_context_guard_reason": None,
                "rag_context_guard_matched_attack": None,
                "rag_context_guard_matched_segment": None,
                "retrieved_results": [],
                "context": "",
                "response": (
                    "Request blocked by the semantic security layer."
                ),
            }

        # -----------------------------------------------------
        # Layer 3: retrieval
        # -----------------------------------------------------

        results = self.retriever.search(
            query=query,
            top_k=top_k,
        )

        context = self._build_context_text(
            results
        )

        # -----------------------------------------------------
        # Layer 4: RAG context guard
        # -----------------------------------------------------

        context_result = (
            self.rag_context_guard.assess(
                context
            )
        )

        if context_result.decision == "BLOCK":
            return {
                "query": query,
                "guard_decision": "BLOCK",
                "guard_layer": "rag_context_guard",
                "guard_risk_score": (
                    context_result.risk_score
                ),
                "guard_reason": (
                    context_result.reason
                ),
                "input_guard_decision": input_result.decision,
                "semantic_guard_decision": semantic_result.decision,
                "semantic_guard_risk_score": (
                    semantic_result.risk_score
                ),
                "semantic_guard_reason": (
                    semantic_result.reason
                ),
                "rag_context_guard_decision": (
                    context_result.decision
                ),
                "rag_context_guard_risk_score": (
                    context_result.risk_score
                ),
                "rag_context_guard_reason": (
                    context_result.reason
                ),
                "rag_context_guard_matched_attack": (
                    context_result.matched_attack
                ),
                "rag_context_guard_matched_segment": (
                    context_result.matched_segment
                ),
                "retrieved_results": results,
                "context": context,
                "response": (
                    "Request blocked because potentially "
                    "malicious instructions were detected "
                    "inside the retrieved RAG context."
                ),
            }

        # -----------------------------------------------------
        # Layer 5: normal RAG generation
        # -----------------------------------------------------

        prompt = build_security_analysis_prompt(
            query=query,
            context=context,
        )

        response = self.llm.generate(
            prompt
        )

        return {
            "query": query,
            "guard_decision": "ALLOW",
            "guard_layer": "none",
            "guard_risk_score": 0.0,
            "guard_reason": "security_checks_passed",
            "input_guard_decision": input_result.decision,
            "semantic_guard_decision": semantic_result.decision,
            "semantic_guard_risk_score": (
                semantic_result.risk_score
            ),
            "semantic_guard_reason": (
                semantic_result.reason
            ),
            "rag_context_guard_decision": (
                context_result.decision
            ),
            "rag_context_guard_risk_score": (
                context_result.risk_score
            ),
            "rag_context_guard_reason": (
                context_result.reason
            ),
            "rag_context_guard_matched_attack": (
                context_result.matched_attack
            ),
            "rag_context_guard_matched_segment": (
                context_result.matched_segment
            ),
            "retrieved_results": results,
            "context": context,
            "response": response,
        }