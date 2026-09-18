from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ThreatAssessment(BaseModel):
    """
    Structured, machine-readable output of an LLM's analysis of a
    security alert -- what turns free-text analysis into something a
    downstream decision/playbook step can actually branch on, instead
    of a human re-reading prose to figure out what to do next.
    """

    threat_type: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    recommended_actions: list[str] = Field(default_factory=list)
