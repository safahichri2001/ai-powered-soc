from __future__ import annotations

from agent.analysis.threat_assessment_parser import parse_threat_assessment


WELL_FORMED = """
<THREAT_ASSESSMENT>
{
  "threat_type": "SSH Brute Force",
  "risk_level": "HIGH",
  "confidence": 0.94,
  "summary": "Multiple failed logins from a single source IP.",
  "recommended_actions": ["Block source IP", "Review account activity"]
}
</THREAT_ASSESSMENT>
"""


def test_parses_well_formed_block():
    result = parse_threat_assessment(WELL_FORMED)

    assert result is not None
    assert result.threat_type == "SSH Brute Force"
    assert result.risk_level == "HIGH"
    assert result.confidence == 0.94
    assert result.recommended_actions == [
        "Block source IP",
        "Review account activity",
    ]


def test_parses_json_with_surrounding_prose():
    """
    Small local models frequently ignore "respond with EXACTLY one
    block" and add commentary before/after -- the parser must still
    find the JSON.
    """

    text = (
        "Sure, here is my analysis:\n\n"
        "<THREAT_ASSESSMENT>\n"
        '{"threat_type": "Port Scan", "risk_level": "MEDIUM", '
        '"confidence": 0.6, "summary": "Scan detected.", '
        '"recommended_actions": []}\n'
        "</THREAT_ASSESSMENT>\n\n"
        "Let me know if you need more detail."
    )

    result = parse_threat_assessment(text)

    assert result is not None
    assert result.threat_type == "Port Scan"


def test_falls_back_to_bare_json_without_tags():
    text = (
        'Here is the assessment: {"threat_type": "Malware", '
        '"risk_level": "CRITICAL", "confidence": 0.99, '
        '"summary": "Known malware signature.", '
        '"recommended_actions": ["Isolate host"]}'
    )

    result = parse_threat_assessment(text)

    assert result is not None
    assert result.threat_type == "Malware"
    assert result.risk_level == "CRITICAL"


def test_returns_none_on_missing_json():
    result = parse_threat_assessment(
        "This looks like a routine SSH login, nothing suspicious."
    )

    assert result is None


def test_returns_none_on_malformed_json():
    text = "<THREAT_ASSESSMENT>{not valid json at all</THREAT_ASSESSMENT>"

    assert parse_threat_assessment(text) is None


def test_returns_none_on_invalid_risk_level():
    """Schema mismatch (hallucinated field value) must not crash."""

    text = (
        "<THREAT_ASSESSMENT>"
        '{"threat_type": "X", "risk_level": "SUPER_HIGH", '
        '"confidence": 0.5, "summary": "y", "recommended_actions": []}'
        "</THREAT_ASSESSMENT>"
    )

    assert parse_threat_assessment(text) is None


def test_returns_none_on_confidence_out_of_range():
    text = (
        "<THREAT_ASSESSMENT>"
        '{"threat_type": "X", "risk_level": "LOW", '
        '"confidence": 1.5, "summary": "y", "recommended_actions": []}'
        "</THREAT_ASSESSMENT>"
    )

    assert parse_threat_assessment(text) is None


def test_returns_none_on_empty_string():
    assert parse_threat_assessment("") is None


def test_returns_none_when_json_is_not_an_object():
    text = "<THREAT_ASSESSMENT>[1, 2, 3]</THREAT_ASSESSMENT>"

    assert parse_threat_assessment(text) is None
