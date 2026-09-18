from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent.models.security_alert import SecurityAlert
from agent.models.threat_assessment import ThreatAssessment
from agent.tools.executor import ToolExecutionResult, ToolExecutor


@dataclass(frozen=True)
class ProposedAction:
    """
    One action a response plan proposes -- never executed on its
    own. `reason` exists so a human reviewing the plan sees exactly
    why it was proposed, not just what it does.
    """

    tool_name: str
    tool_parameters: dict[str, Any]
    reason: str
    requires_approval: bool = True


def build_response_plan(
    alert: SecurityAlert,
    threat_assessment: ThreatAssessment | None,
) -> list[ProposedAction]:
    """
    Deterministically propose response actions from structured,
    validated fields only -- `threat_assessment.risk_level` (a
    constrained Literal) and fixed alert fields (source_ip, agent_id).

    Never reads `threat_assessment.recommended_actions` (free text
    from the LLM) to decide what to do: parsing a model's prose as a
    command is exactly the attack surface this project has avoided
    everywhere else (see LiveAlertInvestigator._enrich's docstring).
    The free text stays visible to a human for context; it never
    drives an action by itself.

    Every action returned has requires_approval=True -- this
    function only ever proposes, it does not execute. State-changing
    actions remain a human decision, same principle as the rest of
    the project.
    """

    if threat_assessment is None:
        return []

    actions: list[ProposedAction] = []

    if threat_assessment.risk_level == "CRITICAL":
        if alert.agent_id and alert.agent_id != "unknown":
            actions.append(
                ProposedAction(
                    tool_name="WazuhIsolateAgent",
                    tool_parameters={"agent_id": alert.agent_id},
                    reason=(
                        f"CRITICAL risk ({threat_assessment.threat_type}) "
                        f"on agent {alert.agent_id} -- isolate to contain."
                    ),
                )
            )

    if threat_assessment.risk_level in ("HIGH", "CRITICAL"):
        if alert.source_ip:
            actions.append(
                ProposedAction(
                    tool_name="FirewallBlockIndicator",
                    tool_parameters={"indicator": alert.source_ip},
                    reason=(
                        f"{threat_assessment.risk_level} risk "
                        f"({threat_assessment.threat_type}) from "
                        f"{alert.source_ip} -- block source."
                    ),
                )
            )

    return actions


def execute_proposed_action(
    action: ProposedAction,
    tool_executor: ToolExecutor,
    approved_by: str,
) -> ToolExecutionResult:
    """
    Execute a proposed action a human has explicitly approved.

    Approval decides whether this call happens at all -- it does
    NOT bypass ToolMisuseGuard. The call still goes through
    ToolExecutor exactly like any other tool call, so a plan built
    from a poisoned/manipulated assessment still can't force an
    action the guard would otherwise reject.
    """

    return tool_executor.run(
        user_instruction=f"[Approved by {approved_by}] {action.reason}",
        tool_name=action.tool_name,
        tool_parameters=action.tool_parameters,
    )
