from __future__ import annotations

import json
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from agent.analysis.approval_policy import PolicyError
from agent.analysis.live_alert_investigator import LiveAlertInvestigator
from agent.analysis.soar_playbook import ProposedAction, execute_proposed_action
from agent.tools.executor import ToolExecutor
from api.dependencies import get_investigator, get_tool_executor
from api.schemas import (
    ApproveActionRequest,
    InvestigationResult,
    ToolExecutionResultOut,
    proposed_action_out,
    tool_execution_result_out,
)

app = FastAPI(
    title="AI-Powered SOC API",
    description=(
        "Read-only alert investigation plus human-approved SOAR "
        "action execution, on top of LiveAlertInvestigator. Every "
        "state-changing action still goes through ToolMisuseGuard "
        "and the RBAC approval policy -- this API adds no bypass."
    ),
)


def _to_investigation_result(entry: dict[str, Any]) -> InvestigationResult:
    return InvestigationResult(
        alert=entry.get("alert"),
        normalization_error=entry.get("normalization_error"),
        analysis=entry.get("analysis"),
        threat_assessment=entry.get("threat_assessment"),
        response_plan=[
            proposed_action_out(action)
            for action in entry.get("response_plan", [])
        ],
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/alerts/recent", response_model=list[InvestigationResult])
def get_recent_alerts(
    limit: int = 5,
    top_k: int = 3,
    investigator: LiveAlertInvestigator = Depends(get_investigator),
) -> list[InvestigationResult]:
    """
    Re-analyzes the `limit` most recent alerts on every call --
    does not touch the watermark. Use /alerts/poll for incremental,
    scheduler-friendly polling that doesn't re-analyze old alerts.
    """

    results = investigator.investigate_recent(limit=limit, top_k=top_k)
    return [_to_investigation_result(entry) for entry in results]


@app.get("/alerts/poll", response_model=list[InvestigationResult])
def poll_new_alerts(
    limit: int = 50,
    top_k: int = 3,
    investigator: LiveAlertInvestigator = Depends(get_investigator),
) -> list[InvestigationResult]:
    """
    Returns only alerts newer than the last call's watermark and
    advances it -- calling this twice in a row with nothing new
    arriving in between returns an empty list. This is what the
    dashboard polls on a timer.
    """

    results = investigator.investigate_new(limit=limit, top_k=top_k)
    return [_to_investigation_result(entry) for entry in results]


@app.get("/analysis/log")
def get_analysis_log(
    limit: int = 50,
    investigator: LiveAlertInvestigator = Depends(get_investigator),
) -> list[dict[str, Any]]:
    """
    Returns the last `limit` entries from the persisted analysis
    log (logs/alert_analysis_log.jsonl by default) -- history that
    survives across polls, unlike /alerts/recent or /alerts/poll
    which only ever reflect the current watermark position.
    """

    path = investigator.analysis_log_path

    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    return entries[-limit:]


@app.post("/actions/approve", response_model=ToolExecutionResultOut)
def approve_action(
    request: ApproveActionRequest,
    tool_executor: ToolExecutor = Depends(get_tool_executor),
) -> ToolExecutionResultOut:
    """
    Execute a human-approved SOAR action. Rebuilds the exact
    ProposedAction from the request body and calls
    execute_proposed_action() -- the same function
    agent/analysis/soar_playbook.py exposes -- so this endpoint
    cannot skip check_approval() (token + role) or ToolMisuseGuard;
    it is not a second, weaker execution path.
    """

    action = ProposedAction(
        tool_name=request.tool_name,
        tool_parameters=request.tool_parameters,
        reason=request.reason,
        risk_level=request.risk_level,
    )

    try:
        result = execute_proposed_action(
            action,
            tool_executor,
            approved_by=request.approved_by,
            approver_role=request.approver_role,
            confirmation_token=request.confirmation_token,
        )
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return tool_execution_result_out(result)
