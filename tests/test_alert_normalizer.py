from agent.preprocessing.normalizer import normalize_wazuh_alert


def test_normalize_wazuh_alert() -> None:
    raw_alert = {
        "timestamp": "2026-08-22T10:19:28.874+0000",
        "rule": {
            "id": "5715",
            "description": "sshd: authentication success.",
            "level": 3,
            "groups": [
                "syslog",
                "sshd",
                "authentication_success",
            ],
            "mitre": {
                "id": ["T1078", "T1021"],
                "tactic": [
                    "Defense Evasion",
                    "Persistence",
                ],
                "technique": [
                    "Valid Accounts",
                    "Remote Services",
                ],
            },
        },
        "agent": {
            "id": "001",
            "name": "Kali",
        },
        "data": {
            "srcip": "10.0.0.20",
            "srcport": "54321",
            "dstuser": "kali",
        },
    }

    alert = normalize_wazuh_alert(raw_alert)

    assert alert.rule_id == "5715"
    assert alert.severity == 3
    assert alert.agent_name == "Kali"
    assert alert.source_ip == "10.0.0.20"
    assert alert.source_port == 54321
    assert alert.user == "kali"