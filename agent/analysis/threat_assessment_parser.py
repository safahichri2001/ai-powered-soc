from __future__ import annotations

import json
import re

from pydantic import ValidationError

from agent.models.threat_assessment import ThreatAssessment

_TAG_PATTERN = re.compile(
    r"<THREAT_ASSESSMENT>\s*(\{.*?\})\s*</THREAT_ASSESSMENT>",
    re.DOTALL,
)

_FALLBACK_JSON_PATTERN = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_blob(text: str) -> str | None:
    """Prefer the delimited block; fall back to the first {...} found."""

    tag_match = _TAG_PATTERN.search(text)

    if tag_match:
        return tag_match.group(1)

    fallback_match = _FALLBACK_JSON_PATTERN.search(text)

    if fallback_match:
        return fallback_match.group(0)

    return None


def parse_threat_assessment(llm_response: str) -> ThreatAssessment | None:
    """
    Parse a ThreatAssessment out of raw LLM text.

    Returns None on ANY failure (missing block, invalid JSON, schema
    mismatch) rather than raising. LLM output is untrusted and
    unreliable -- a small local model can drop the delimiters, emit
    malformed JSON, or hallucinate a field -- so a parsing failure
    must degrade gracefully (the caller falls back to the free-text
    analysis) and never crash the pipeline.
    """

    if not llm_response:
        return None

    blob = _extract_json_blob(llm_response)

    if blob is None:
        return None

    try:
        payload = json.loads(blob)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    try:
        return ThreatAssessment.model_validate(payload)
    except ValidationError:
        return None
