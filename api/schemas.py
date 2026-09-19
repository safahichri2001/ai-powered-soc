from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

from agent.analysis.approval_policy import generate_confirmation_token
from agent.analysis.soar_playbook import ProposedAction
from agent.models.security_alert import SecurityAlert
from agent.models.threat_assessment import ThreatAssessment
from agent.tools.executor import ToolExecutionResult

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ProposedActionOut(BaseModel):
    """
    Mirrors agent.analysis.soar_playbook.ProposedAction for API
    responses, plus the confirmation_token a human needs to approve
    it -- computed server-side so the dashboard never has to
    reimplement the hashing in JavaScript, and so a tampered
    tool_name/tool_parameters sent back on approval is caught by
    check_approval() rather than trusted.
    """

    tool_name: str
    tool_parameters: dict[str, Any]
    reason: str
    risk_level: RiskLevel
    requires_approval: bool
    confirmation_token: str


def proposed_action_out(action: ProposedAction) -> ProposedActionOut:
    return ProposedActionOut(
        tool_name=action.tool_name,
        tool_parameters=action.tool_parameters,
        reason=action.reason,
        risk_level=action.risk_level,  # type: ignore[arg-type]
        requires_approval=action.requires_approval,
        confirmation_token=generate_confirmation_token(action),
    )


class InvestigationResult(BaseModel):
    """
    One entry of what LiveAlertInvestigator.investigate_recent() /
    investigate_new() returns, reshaped for JSON. `analysis` is left
    as a loose dict (its shape comes from RAGPipeline.analyze() and
    isn't itself a stable schema yet) rather than modeled field by
    field.
    """

    alert: SecurityAlert | None
    normalization_error: str | None
    analysis: dict[str, Any] | None = None
    threat_assessment: ThreatAssessment | None = None
    response_plan: list[ProposedActionOut] = []


class ApproveActionRequest(BaseModel):
    """
    Body of POST /actions/approve. Mirrors ProposedAction's own
    fields -- the caller must send back exactly what was proposed,
    since check_approval() re-derives the token from these same
    fields and rejects the request if anything was changed -- plus
    who is approving it and with what role.
    """

    tool_name: str
    tool_parameters: dict[str, Any]
    reason: str
    risk_level: RiskLevel
    approved_by: str
    approver_role: str
    confirmation_token: str


class ToolExecutionResultOut(BaseModel):
    """
    Mirrors agent.tools.executor.ToolExecutionResult. Only the
    guard's decision/reason are surfaced (not the full
    ToolMisuseGuardResult) -- that's what the dashboard needs to
    explain an outcome to a human; the rest stays in the audit log.
    """

    status: Literal["EXECUTED", "BLOCKED", "ERROR"]
    tool_name: str
    output: dict[str, Any] | None
    guard_decision: str | None
    guard_reason: str | None


def tool_execution_result_out(
    result: ToolExecutionResult,
) -> ToolExecutionResultOut:
    return ToolExecutionResultOut(
        status=result.status,  # type: ignore[arg-type]
        tool_name=result.tool_name,
        output=result.output,
        guard_decision=(
            result.guard_result.decision if result.guard_result else None
        ),
        guard_reason=(
            result.guard_result.reason if result.guard_result else None
        ),
    )
