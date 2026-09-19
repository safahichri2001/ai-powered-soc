from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent.analysis.soar_playbook import ProposedAction


class PolicyError(RuntimeError):
    """
    Raised when an action cannot be executed because the approval
    policy rejects it -- wrong/missing confirmation token, or an
    approver role too low for the action's risk level. Distinct
    from a ToolMisuseGuard BLOCK: this is a policy/authorization
    check that happens BEFORE the guard is ever consulted, not a
    content-based risk judgment.
    """


# Minimum role required to approve an action at each risk level.
# None means no formal approval requirement (build_response_plan
# currently never proposes an action for LOW/MEDIUM anyway).
APPROVAL_REQUIREMENTS: dict[str, str | None] = {
    "LOW": None,
    "MEDIUM": None,
    "HIGH": "analyst",
    "CRITICAL": "admin",
}

# Higher number = more authority. An "admin" can approve anything
# an "analyst" can.
ROLE_HIERARCHY: dict[str, int] = {
    "analyst": 1,
    "admin": 2,
}


def generate_confirmation_token(action: "ProposedAction") -> str:
    """
    Derive a short token from an action's exact content (tool,
    parameters, reason, risk level). execute_proposed_action()
    requires this token to be echoed back, proving the caller is
    acting on the SPECIFIC action that was reviewed -- not a
    different one, and not a stale/modified copy of it.

    Not a cryptographic secret -- there's nothing to keep hidden
    here, it's a content-integrity check, not an authentication
    mechanism. Its job is to catch "wrong action" and "action
    changed after being shown," not to stop a determined attacker.
    """

    payload = json.dumps(
        {
            "tool_name": action.tool_name,
            "tool_parameters": action.tool_parameters,
            "reason": action.reason,
            "risk_level": action.risk_level,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def check_approval(
    action: "ProposedAction",
    approver_role: str,
    confirmation_token: str,
) -> None:
    """
    Raise PolicyError if this action cannot be approved by this
    role with this token. Returns normally (does nothing) if the
    approval is valid.
    """

    expected_token = generate_confirmation_token(action)

    if confirmation_token != expected_token:
        raise PolicyError(
            "Confirmation token does not match this action's content -- "
            "refusing to execute. This means either the wrong token was "
            "supplied, or the action was modified after being proposed."
        )

    required_role = APPROVAL_REQUIREMENTS.get(action.risk_level)

    if required_role is None:
        return

    if approver_role not in ROLE_HIERARCHY:
        raise PolicyError(f"Unknown approver role: '{approver_role}'.")

    if ROLE_HIERARCHY[approver_role] < ROLE_HIERARCHY[required_role]:
        raise PolicyError(
            f"Role '{approver_role}' cannot approve a "
            f"{action.risk_level}-risk action -- requires at least "
            f"'{required_role}'."
        )
