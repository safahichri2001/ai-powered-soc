from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from agent.analysis.alert_status_store import AlertStatusStore
from agent.analysis.approval_policy import PolicyError
from agent.analysis.live_alert_investigator import LiveAlertInvestigator
from agent.analysis.soar_playbook import ProposedAction, execute_proposed_action
from agent.integrations.wazuh_client import WazuhClientError, WazuhManagerClient
from agent.tools.executor import ToolExecutor
from api.dependencies import get_alert_status_store, get_investigator, get_tool_executor
from api.schemas import (
    AlertStatusRequest,
    ApproveActionRequest,
    InvestigationResult,
    RejectActionRequest,
    ToolExecutionResultOut,
    proposed_action_out,
    tool_execution_result_out,
)

DECISIONS_LOG_PATH = Path("logs/analyst_decisions.jsonl")

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
        alert_id=(entry.get("raw_alert") or {}).get("id"),
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


@app.get("/agents/count")
def get_agents_count() -> dict[str, Any]:
    """
    Real count of Wazuh-monitored agents, for the dashboard's
    "Agents surveillés" tile -- queries the Manager API directly
    rather than hardcoding a number that would go stale.
    """

    try:
        agents = WazuhManagerClient().list_agents()
        return {"count": len(agents), "available": True}
    except WazuhClientError:
        return {"count": None, "available": False}


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
    since_hours: float | None = None,
    investigator: LiveAlertInvestigator = Depends(get_investigator),
) -> list[dict[str, Any]]:
    """
    Returns entries from the persisted analysis log
    (logs/alert_analysis_log.jsonl by default) -- history that
    survives across polls, unlike /alerts/recent or /alerts/poll
    which only ever reflect the current watermark position.

    `limit` (last N lines) and `since_hours` (last N hours, by each
    entry's own alert timestamp) are different things and were
    previously conflated: a caller asking for "the last 24 hours"
    via `limit=500` alone would silently undercount on a
    high-volume day, once more than 500 lines had been written
    within that window -- the oldest ones in range would already
    have fallen off the tail. Pass `since_hours` for a real time
    window; `limit` still applies afterwards as a sane upper bound,
    not as the window itself.
    """

    path = investigator.analysis_log_path

    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]

    if since_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        entries = [
            entry
            for entry in entries
            if (parsed := _parse_timestamp(entry.get("timestamp")))
            and parsed >= cutoff
        ]

    return entries[-limit:]


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


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
            justification=request.justification,
            alert_id=request.alert_id,
        )
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return tool_execution_result_out(result)


@app.post("/actions/reject")
def reject_action(request: RejectActionRequest) -> dict[str, Any]:
    """
    Record that a human reviewed a proposed action and declined to
    approve it. Nothing executes and no guard/RBAC check applies --
    declining to act is always safe -- this only appends an entry
    to DECISIONS_LOG_PATH so the decision has an audit trail too,
    not just approvals.
    """

    DECISIONS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": time.time(),
        "decision": "REJECTED",
        "tool_name": request.tool_name,
        "tool_parameters": request.tool_parameters,
        "reason": request.reason,
        "risk_level": request.risk_level,
        "reviewed_by": request.reviewed_by,
        "justification": request.justification,
        "alert_id": request.alert_id,
    }

    with DECISIONS_LOG_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

    return entry


@app.get("/audit/log")
def get_audit_log(
    limit: int = 50,
    tool_executor: ToolExecutor = Depends(get_tool_executor),
) -> list[dict[str, Any]]:
    """
    Merges ToolExecutor's own audit log (every guarded run attempt,
    EXECUTED/BLOCKED/ERROR) with DECISIONS_LOG_PATH (REJECTED
    entries, which never reach ToolExecutor since nothing runs),
    newest first -- one real decision trail for the dashboard
    instead of two separate files.
    """

    entries: list[dict[str, Any]] = []

    for path in (tool_executor.audit_log_path, DECISIONS_LOG_PATH):
        if not path.exists():
            continue

        lines = path.read_text(encoding="utf-8").splitlines()
        entries.extend(json.loads(line) for line in lines if line.strip())

    entries.sort(key=lambda entry: entry["timestamp"], reverse=True)
    return entries[:limit]


@app.get("/alerts/status")
def get_alert_statuses(
    store: AlertStatusStore = Depends(get_alert_status_store),
) -> dict[str, Any]:
    """
    All analyst-set alert statuses (resolved/deleted), keyed by
    alert_id. Wazuh has no concept of this -- it's purely dashboard
    state layered on top, so the frontend fetches it separately and
    filters resolved/deleted alerts out of its own view.
    """

    return store.get_all()


@app.post("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: str,
    request: AlertStatusRequest,
    store: AlertStatusStore = Depends(get_alert_status_store),
) -> dict[str, Any]:
    """
    Marks an alert reviewed and removes it from the main dashboard
    view. Nothing about the alert, its analysis, or any audit/
    decision log entry is touched -- purely a display-state flag,
    reversible by an operator editing logs/alert_status.json.
    """

    return store.set_status(alert_id, "resolved", by=request.by)


@app.post("/alerts/{alert_id}/delete")
def delete_alert(
    alert_id: str,
    request: AlertStatusRequest,
    store: AlertStatusStore = Depends(get_alert_status_store),
) -> dict[str, Any]:
    """
    Permanently hides an alert from the dashboard. Despite the name,
    this does not erase the underlying Wazuh alert or any audit/
    decision log entry tied to it -- only the dashboard's own
    display-state file is written to, so the audit trail this
    project relies on for auditability is never at risk from this
    endpoint.
    """

    return store.set_status(alert_id, "deleted", by=request.by)


DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "dashboard"

app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_DIR, html=True),
    name="dashboard",
)
