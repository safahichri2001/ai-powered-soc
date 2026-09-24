from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.security.tool_misuse_guard import (
    ToolMisuseGuard,
    ToolMisuseGuardResult,
)
from agent.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ToolExecutionResult:
    """Outcome of a `ToolExecutor.run()` call."""

    status: str  # "EXECUTED" | "BLOCKED" | "ERROR"
    tool_name: str
    output: dict[str, Any] | None
    guard_result: ToolMisuseGuardResult | None


class ToolExecutor:
    """
    Single choke point between an agent's intent to call a tool and
    the tool's handler actually running.

    Security property this class exists to guarantee:

        No tool handler is ever invoked unless ToolMisuseGuard has
        first evaluated the (instruction, tool, parameters) triple
        and returned ALLOW.

    Nothing else in the codebase should call `tool.handler(...)`
    directly -- doing so bypasses the guard entirely.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        guard: ToolMisuseGuard | None = None,
        audit_log_path: str | Path = "logs/tool_execution_audit.jsonl",
    ) -> None:
        self.registry = registry
        self.guard = guard or ToolMisuseGuard()
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        user_instruction: str,
        tool_name: str,
        tool_parameters: dict[str, Any] | None = None,
        alert_id: str | None = None,
        justification: str = "",
    ) -> ToolExecutionResult:
        """
        Assess a tool call and execute it only if the guard allows
        it. `alert_id` is optional, audit-only metadata (which
        displayed alert this call was for, if any) -- it plays no
        role in the guard decision.

        `justification` (a human analyst's free-text note, when this
        call comes from an approved SOAR action) is recorded in the
        audit entry but deliberately NOT passed to the guard: it's
        unpredictable human-written text, and folding it into the
        same string the guard scans for dangerous intent means an
        analyst's own ordinary vocabulary ("blocking this IP",
        "restricting this source") could trip a false BLOCK on the
        very action they just approved. The guard still evaluates
        `user_instruction` in full -- only the analyst's own note is
        kept out of that evaluation.
        """

        tool_parameters = tool_parameters or {}

        tool = self.registry.get(tool_name)

        if tool is None:
            result = ToolExecutionResult(
                status="ERROR",
                tool_name=tool_name,
                output={"error": f"unknown_tool:{tool_name}"},
                guard_result=None,
            )
            self._audit(user_instruction, tool_name, tool_parameters, result, alert_id, justification)
            return result

        guard_result = self.guard.assess(
            user_instruction=user_instruction,
            tool_name=tool_name,
            tool_parameters=tool_parameters,
        )

        if guard_result.decision == "BLOCK":
            result = ToolExecutionResult(
                status="BLOCKED",
                tool_name=tool_name,
                output=None,
                guard_result=guard_result,
            )
            self._audit(user_instruction, tool_name, tool_parameters, result, alert_id, justification)
            return result

        try:
            output = tool.handler(**tool_parameters)
            status = "EXECUTED"

        except Exception as exc:
            output = {"error": str(exc)}
            status = "ERROR"

        result = ToolExecutionResult(
            status=status,
            tool_name=tool_name,
            output=output,
            guard_result=guard_result,
        )
        self._audit(user_instruction, tool_name, tool_parameters, result, alert_id, justification)
        return result

    def _audit(
        self,
        user_instruction: str,
        tool_name: str,
        tool_parameters: dict[str, Any],
        result: ToolExecutionResult,
        alert_id: str | None = None,
        justification: str = "",
    ) -> None:
        """Append one structured record per decision, blocks included."""

        entry = {
            "timestamp": time.time(),
            "user_instruction": user_instruction,
            "tool_name": tool_name,
            "tool_parameters": tool_parameters,
            "status": result.status,
            "risk_score": (
                result.guard_result.risk_score
                if result.guard_result
                else None
            ),
            "matched_attack": (
                result.guard_result.matched_attack
                if result.guard_result
                else None
            ),
            "alert_id": alert_id,
            "justification": justification,
        }

        with self.audit_log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(entry) + "\n")
