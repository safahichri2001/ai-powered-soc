from agent.models.security_alert import SecurityAlert


def format_alert_for_ai(alert: SecurityAlert) -> str:
    """Convert a normalized security alert into an AI-friendly text representation."""

    lines = [
        "Security Alert",
        f"Timestamp: {alert.timestamp.isoformat()}",
        f"Rule ID: {alert.rule_id}",
        f"Description: {alert.rule_description}",
        f"Severity: {alert.severity}",
        f"Agent: {alert.agent_name} (ID: {alert.agent_id})",
    ]

    if alert.event_type:
        lines.append(f"Event type: {alert.event_type}")

    if alert.source_ip:
        lines.append(f"Source IP: {alert.source_ip}")

    if alert.source_port is not None:
        lines.append(f"Source port: {alert.source_port}")

    if alert.destination_ip:
        lines.append(f"Destination IP: {alert.destination_ip}")

    if alert.destination_port is not None:
        lines.append(f"Destination port: {alert.destination_port}")

    if alert.user:
        lines.append(f"User: {alert.user}")

    mitre = alert.metadata.get("mitre", {})
    if mitre:
        lines.append(f"MITRE information: {mitre}")

    return "\n".join(lines)