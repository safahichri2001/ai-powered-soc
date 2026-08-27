from dataclasses import dataclass
import re

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim

from agent.security.bipia_attack_store import (
    BIPIAAttackStore,
)


@dataclass(frozen=True)
class RAGContextGuardResult:
    """Result of retrieved-context security analysis."""

    decision: str
    risk_score: float
    reason: str
    matched_attack: str | None = None
    matched_segment: str | None = None


class RAGContextGuard:
    """
    Hybrid detector for indirect prompt injections
    inside retrieved RAG context.

    Detection layers:
    1. Explicit rule-based detection.
    2. Semantic similarity against BIPIA attack references.
    """

    DEFAULT_PATTERNS = (
        r"\bignore\s+(all\s+)?previous\s+instructions\b",
        r"\bignore\s+(the\s+)?security\s+(analysis\s+)?rules\b",
        r"\bdisregard\s+(all\s+)?previous\s+(instructions|guidance)\b",
        r"\bsystem\s+(message|instruction|rule)\b",
        r"\bimportant\s+instruction\s+(for\s+the\s+ai|for\s+the\s+assistant)\b",
        r"\bnew\s+system\s+rule\b",
        r"\bsystem\s+override\b",
        r"\bassistant\s+(directive|instruction)\b",
        r"\btreat\s+this\s+document\s+as\s+(higher|high)\s+priority\b",
        r"\boverride\s+the\s+(current|existing)\s+(policy|instructions|guidance)\b",
        r"\bdisregard\s+all\s+(security|safety)\s+guidance\b",
        r"\bdo\s+not\s+use\s+the\s+retrieved\s+security\s+context\b",
    )

    def __init__(
        self,
        model_name: str = (
            "sentence-transformers/all-MiniLM-L6-v2"
        ),
        threshold: float = 0.40,
        attack_file: str = (
            "data/external/bipia/raw/"
            "BIPIA-main/benchmark/"
            "text_attack_train.json"
        ),
        patterns: tuple[str, ...] | None = None,
    ) -> None:
        """
        Initialize the RAG context guard.

        Args:
            model_name:
                Sentence-Transformer model used for semantic matching.

            threshold:
                Initial semantic similarity threshold.
                This value will be calibrated separately for RAG
                context detection.

            attack_file:
                BIPIA attack reference file.

            patterns:
                Optional custom explicit detection patterns.
        """

        self.model = SentenceTransformer(
            model_name
        )

        self.threshold = threshold

        self.attack_store = BIPIAAttackStore(
            attack_file=attack_file,
            model=self.model,
        )

        selected_patterns = (
            patterns
            if patterns is not None
            else self.DEFAULT_PATTERNS
        )

        self.compiled_patterns = [
            re.compile(
                pattern,
                flags=re.IGNORECASE,
            )
            for pattern in selected_patterns
        ]

    def _split_context(
        self,
        context: str,
    ) -> list[str]:
        """
        Split retrieved context into candidate segments.

        Newline boundaries are used first because indirect
        instructions are frequently inserted as independent
        lines in the poisoned context.
        """

        segments = [
            part.strip()
            for part in context.splitlines()
            if part.strip()
        ]

        if not segments:
            return [context.strip()]

        return segments

    def _check_rules(
        self,
        context: str,
    ) -> str | None:
        """Return the first matching explicit rule."""

        for pattern in self.compiled_patterns:
            match = pattern.search(context)

            if match:
                return match.group(0)

        return None

    def _similarity_matrix(
        self,
        segment_embeddings,
    ):
        """Compute similarity between context segments and BIPIA attacks."""

        return cos_sim(
            segment_embeddings,
            self.attack_store.embeddings,
        )

    def assess(
        self,
        context: str,
    ) -> RAGContextGuardResult:
        """
        Assess retrieved RAG context for indirect prompt injection.

        Detection is performed in two layers:

        1. Explicit rule matching.
        2. Semantic similarity against BIPIA attack references.
        """

        if not context or not context.strip():
            return RAGContextGuardResult(
                decision="BLOCK",
                risk_score=1.0,
                reason="empty_context",
                matched_attack=None,
                matched_segment=None,
            )

        clean_context = context.strip()

        # -----------------------------------------------------
        # Layer 1: explicit rule-based detection
        # -----------------------------------------------------

        rule_match = self._check_rules(
            clean_context
        )

        if rule_match is not None:
            return RAGContextGuardResult(
                decision="BLOCK",
                risk_score=1.0,
                reason=(
                    "indirect_prompt_injection_detected"
                ),
                matched_attack=rule_match,
                matched_segment=clean_context,
            )

        # -----------------------------------------------------
        # Layer 2: semantic detection
        # -----------------------------------------------------

        segments = self._split_context(
            clean_context
        )

        segment_embeddings = self.model.encode(
            segments,
            normalize_embeddings=True,
            convert_to_tensor=True,
        )

        similarity_matrix = self._similarity_matrix(
            segment_embeddings
        )

        max_score_tensor = similarity_matrix.max()

        max_score = float(
            max_score_tensor.item()
        )

        max_position = int(
            similarity_matrix.argmax().item()
        )

        attack_count = self.attack_store.size

        segment_index = (
            max_position // attack_count
        )

        attack_index = (
            max_position % attack_count
        )

        matched_segment = segments[
            segment_index
        ]

        matched_attack = (
            self.attack_store.attacks[
                attack_index
            ]
        )

        if max_score >= self.threshold:
            return RAGContextGuardResult(
                decision="BLOCK",
                risk_score=max_score,
                reason=(
                    "indirect_prompt_injection_detected"
                ),
                matched_attack=matched_attack,
                matched_segment=matched_segment,
            )

        return RAGContextGuardResult(
            decision="ALLOW",
            risk_score=max_score,
            reason="no_indirect_injection_detected",
            matched_attack=None,
            matched_segment=None,
        )