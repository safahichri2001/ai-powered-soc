from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityAlert(BaseModel):
    """Normalized representation of a Wazuh security alert."""

    timestamp: datetime

    rule_id: str
    rule_description: str
    severity: int = Field(ge=0, le=15)

    agent_id: str
    agent_name: str

    event_type: str | None = None

    source_ip: str | None = None
    source_port: int | None = None

    destination_ip: str | None = None
    destination_port: int | None = None

    user: str | None = None

    raw_event: dict[str, Any] = Field(default_factory=dict)

    metadata: dict[str, Any] = Field(default_factory=dict)