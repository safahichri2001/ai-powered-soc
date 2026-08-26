from dataclasses import dataclass
import re


@dataclass(frozen=True)
class GuardResult:
    """Result of the input security assessment."""

    decision: str
    risk_score: float
    reason: str


class InputGuard:
    """Detect common prompt-injection patterns before the RAG pipeline."""

    _PATTERNS = (
        (
            re.compile(
                r"\bignore\s+(all\s+)?previous\s+instructions\b",
                re.IGNORECASE,
            ),
            0.95,
        ),
        (
            re.compile(
                r"\b(reveal|show|print|give)\b.{0,40}\b"
                r"(system\s+prompt|hidden\s+instructions)\b",
                re.IGNORECASE,
            ),
            0.95,
        ),
        (
            re.compile(
                r"\byou\s+are\s+now\b.{0,60}\b"
                r"(unrestricted|different|another)\b",
                re.IGNORECASE,
            ),
            0.85,
        ),
        (
            re.compile(
                r"\bignore\s+(the\s+)?security\s+policy\b",
                re.IGNORECASE,
            ),
            0.95,
        ),
        (
            re.compile(
                r"\b(disregard|ignore|override|replace)\b.{0,60}\b"
                r"(previous|current|provided|existing)\s+"
                r"(instructions?|context|rules?|policy)\b",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            re.compile(
                r"\b(treat|consider)\b.{0,60}\b"
                r"(this|my\s+message)\b.{0,40}\b"
                r"(highest|top|priority)\b",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            re.compile(
                r"\b(follow|obey)\s+my\s+instructions?\s+instead\b",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            re.compile(
                r"\b(bypass|circumvent|disable)\b.{0,50}\b"
                r"(security|safety|policy|control)s?\b",
                re.IGNORECASE,
            ),
            0.90,
        ),
    )

    def assess(self, text: str) -> GuardResult:
        """Assess a user input for common prompt-injection indicators."""

        if not text or not text.strip():
            return GuardResult(
                decision="BLOCK",
                risk_score=1.0,
                reason="empty_input",
            )

        for pattern, score in self._PATTERNS:
            if pattern.search(text):
                return GuardResult(
                    decision="BLOCK",
                    risk_score=score,
                    reason="prompt_injection_detected",
                )

        return GuardResult(
            decision="ALLOW",
            risk_score=0.0,
            reason="no_known_injection_pattern",
        )