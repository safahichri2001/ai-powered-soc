from datetime import datetime, timezone

from agent.models.security_alert import SecurityAlert
from agent.preprocessing.formatter import format_alert_for_ai


def test_format_alert_for_ai() -> None:
    alert = SecurityAlert(
        timestamp=datetime(2026, 8, 22, 10, 19, 28, tzinfo=timezone.utc),
        rule_id="5715",
        rule_description="sshd: authentication success.",
        severity=3,
        agent_id="001",
        agent_name="Kali",
        event_type="sshd",
        source_ip="10.0.0.20",
        source_port=54321,
        user="kali",
        metadata={
            "mitre": {
                "id": ["T1078", "T1021"],
            }
        },
    )

    text = format_alert_for_ai(alert)

    assert "Rule ID: 5715" in text
    assert "Severity: 3" in text
    assert "Agent: Kali" in text
    assert "Source IP: 10.0.0.20" in text
    assert "User: kali" in text