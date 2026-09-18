from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rag.pipeline import RAGPipeline


@dataclass(frozen=True)
class FakeGuardResult:
    decision: str = "ALLOW"
    risk_score: float = 0.0
    reason: str = "fake"
    matched_attack: str | None = None
    matched_segment: str | None = None


class FakeGuard:
    def assess(self, *args, **kwargs) -> FakeGuardResult:
        return FakeGuardResult()


class FakeRetriever:
    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        return [{"content": "some knowledge", "source": "doc.md"}]


class FakeLLM:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return "response"


def _build_pipeline(llm: FakeLLM, prompt_builder=None) -> RAGPipeline:
    return RAGPipeline(
        retriever=FakeRetriever(),
        llm=llm,
        input_guard=FakeGuard(),
        semantic_guard=FakeGuard(),
        rag_context_guard=FakeGuard(),
        prompt_builder=prompt_builder,
    )


def test_default_prompt_builder_is_used_when_none_given():
    llm = FakeLLM()
    pipeline = _build_pipeline(llm)

    pipeline.analyze("How should I investigate this?")

    assert "cybersecurity analyst" in llm.prompts[0]
    assert "THREAT_ASSESSMENT" not in llm.prompts[0]


def test_custom_prompt_builder_is_used_when_given():
    llm = FakeLLM()

    def custom_builder(query: str, context: str) -> str:
        return f"CUSTOM|{query}|{context}"

    pipeline = _build_pipeline(llm, prompt_builder=custom_builder)

    pipeline.analyze("some alert text")

    assert llm.prompts[0].startswith("CUSTOM|some alert text|")


def test_threat_assessment_prompt_builder_asks_for_structured_output():
    from agent.prompts.threat_assessment_prompt import (
        build_threat_assessment_prompt,
    )

    llm = FakeLLM()
    pipeline = _build_pipeline(llm, prompt_builder=build_threat_assessment_prompt)

    pipeline.analyze("Security Alert: sshd authentication failed.")

    assert "THREAT_ASSESSMENT" in llm.prompts[0]
    assert "risk_level" in llm.prompts[0]
