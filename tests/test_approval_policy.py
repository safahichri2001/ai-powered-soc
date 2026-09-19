from __future__ import annotations

import pytest

from agent.analysis.approval_policy import (
    PolicyError,
    check_approval,
    generate_confirmation_token,
)
from agent.analysis.soar_playbook import ProposedAction


def _action(risk_level: str) -> ProposedAction:
    return ProposedAction(
        tool_name="FirewallBlockIndicator",
        tool_parameters={"indicator": "10.0.0.20"},
        reason="test reason",
        risk_level=risk_level,
    )


def test_token_is_deterministic_for_same_action():
    action = _action("HIGH")
    assert generate_confirmation_token(action) == generate_confirmation_token(action)


def test_token_differs_for_different_actions():
    a = _action("HIGH")
    b = _action("CRITICAL")
    assert generate_confirmation_token(a) != generate_confirmation_token(b)


def test_token_differs_when_parameters_change():
    a = ProposedAction(
        tool_name="FirewallBlockIndicator",
        tool_parameters={"indicator": "10.0.0.20"},
        reason="test reason",
        risk_level="HIGH",
    )
    b = ProposedAction(
        tool_name="FirewallBlockIndicator",
        tool_parameters={"indicator": "10.0.0.99"},  # different IP
        reason="test reason",
        risk_level="HIGH",
    )
    assert generate_confirmation_token(a) != generate_confirmation_token(b)


def test_check_approval_passes_with_correct_token_and_sufficient_role():
    action = _action("HIGH")
    check_approval(action, "analyst", generate_confirmation_token(action))
    # No exception raised == success.


def test_check_approval_rejects_wrong_token():
    action = _action("HIGH")
    with pytest.raises(PolicyError, match="does not match"):
        check_approval(action, "analyst", "wrong-token")


def test_check_approval_rejects_unknown_role():
    action = _action("HIGH")
    with pytest.raises(PolicyError, match="Unknown approver role"):
        check_approval(action, "intern", generate_confirmation_token(action))


def test_check_approval_rejects_analyst_for_critical():
    action = _action("CRITICAL")
    with pytest.raises(PolicyError, match="requires at least 'admin'"):
        check_approval(action, "analyst", generate_confirmation_token(action))


def test_check_approval_allows_admin_for_critical():
    action = _action("CRITICAL")
    check_approval(action, "admin", generate_confirmation_token(action))


def test_check_approval_allows_admin_for_high():
    """Higher roles can approve anything a lower role could."""

    action = _action("HIGH")
    check_approval(action, "admin", generate_confirmation_token(action))


def test_check_approval_allows_any_role_for_low_risk():
    """LOW/MEDIUM have no formal requirement (None)."""

    action = _action("LOW")
    check_approval(action, "analyst", generate_confirmation_token(action))
