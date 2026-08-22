# Wazuh Alert Interpretation

A Wazuh alert contains information about a detected security event.

Important fields include:

- Rule ID
- Rule description
- Alert level
- Agent
- Timestamp
- Source IP
- Destination information
- User
- Event data
- MITRE ATT&CK mapping when available

Alert severity alone is not sufficient to determine whether an event is malicious.

An analyst should combine the alert severity, event context, source information,
historical activity, and related events before making a security decision.