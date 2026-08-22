from typing import Any

from agent.llm.ollama_client import OllamaClient
from agent.prompts.security_analysis import build_security_analysis_prompt
from rag.retrieval.context_builder import build_context
from rag.retrieval.retriever import Retriever


class RAGPipeline:
    """Retrieve security knowledge and generate an LLM analysis."""

    def __init__(
        self,
        retriever: Retriever,
        llm: OllamaClient | None = None,
    ) -> None:
        self.retriever = retriever
        self.llm = llm or OllamaClient()

    def analyze(
        self,
        query: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """Run retrieval, context construction, and LLM generation."""

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
            "retrieved_results": results,
            "context": context,
            "response": response,
        }