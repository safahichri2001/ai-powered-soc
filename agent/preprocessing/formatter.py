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

    # Wazuh's own decoders extract structured fields (like `user`)
    # with narrow regexes built for normal values -- an attacker who
    # puts unexpected text where a username/command is read can end
    # up with it silently truncated before it ever reaches `data`
    # (observed live: a multi-word SSH username was cut down to its
    # last token by Wazuh's sshd decoder). full_log is Wazuh's
    # unprocessed copy of the original line, so scanning it too
    # means a decoder losing/mangling a field doesn't also blind the
    # guard to what an attacker actually sent.
    full_log = alert.raw_event.get("full_log")
    if full_log:
        lines.append(f"Raw log: {full_log}")

    return "\n".join(lines)