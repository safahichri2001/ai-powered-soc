from dataclasses import dataclass
from pathlib import Path

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim

from agent.security.reference_attack_store import ReferenceAttackStore


@dataclass(frozen=True)
class SemanticGuardResult:
    """Result of semantic prompt-injection detection."""

    decision: str
    risk_score: float
    reason: str


class SemanticGuard:
    """Detect prompt injections using semantic similarity."""

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        threshold: float = 0.40,
        reference_dataset: str | Path = (
            "data/security/prepared/reference.jsonl"
        ),
    ) -> None:
        self.model = SentenceTransformer(model_name)
        self.threshold = threshold

        self.reference_store = ReferenceAttackStore(
            dataset_path=reference_dataset,
            model=self.model,
        )

    def assess(self, text: str) -> SemanticGuardResult:
        """Assess text against the reference attack corpus."""

        if not text or not text.strip():
            return SemanticGuardResult(
                decision="BLOCK",
                risk_score=1.0,
                reason="empty_input",
            )

        query_embedding = self.model.encode(
            text,
            normalize_embeddings=True,
            convert_to_tensor=True,
        )

        similarities = cos_sim(
            query_embedding,
            self.reference_store.embeddings,
        )[0]

        max_similarity = float(
            similarities.max().item()
        )

        if max_similarity >= self.threshold:
            return SemanticGuardResult(
                decision="BLOCK",
                risk_score=max_similarity,
                reason="semantic_prompt_injection_detected",
            )

        return SemanticGuardResult(
            decision="ALLOW",
            risk_score=max_similarity,
            reason="no_semantic_injection_detected",
        )