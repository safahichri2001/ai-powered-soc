from datetime import datetime
from typing import Any

from agent.models.security_alert import SecurityAlert


def normalize_wazuh_alert(alert: dict[str, Any]) -> SecurityAlert:
    """Convert a raw Wazuh alert into the internal SecurityAlert model."""

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    return SecurityAlert(
        timestamp=datetime.fromisoformat(
            alert["timestamp"].replace("Z", "+00:00")
        ),
        rule_id=str(rule.get("id", "unknown")),
        rule_description=rule.get("description", "Unknown alert"),
        severity=int(rule.get("level", 0)),
        agent_id=str(agent.get("id", "unknown")),
        agent_name=agent.get("name", "unknown"),
        event_type=(
            rule.get("groups", [None])[0]
            if rule.get("groups")
            else None
        ),
        source_ip=data.get("srcip"),
        source_port=_to_int(data.get("srcport")),
        destination_ip=data.get("dstip"),
        destination_port=_to_int(data.get("dstport")),
        user=data.get("dstuser") or data.get("srcuser"),
        raw_event=alert,
        metadata={
            "mitre": rule.get("mitre", {}),
            "groups": rule.get("groups", []),
        },
    )


def _to_int(value: Any) -> int | None:
    """Safely convert a value to an integer."""
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None