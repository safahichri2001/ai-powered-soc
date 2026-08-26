from dataclasses import dataclass

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim


@dataclass(frozen=True)
class SemanticGuardResult:
    """Result of semantic prompt-injection detection."""

    decision: str
    risk_score: float
    reason: str


class SemanticGuard:
    """Detect semantically similar prompt-injection attempts."""

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        threshold: float = 0.75,
    ) -> None:
        self.model = SentenceTransformer(model_name)
        self.threshold = threshold

    def assess(
        self,
        text: str,
        attack_examples: list[str],
    ) -> SemanticGuardResult:
        """Compare the input against known prompt-injection examples."""

        if not text.strip():
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

        example_embeddings = self.model.encode(
            attack_examples,
            normalize_embeddings=True,
            convert_to_tensor=True,
        )

        similarities = cos_sim(
            query_embedding,
            example_embeddings,
        )[0]

        max_similarity = float(similarities.max().item())

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