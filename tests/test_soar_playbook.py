from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from agent.analysis.soar_playbook import (
    ProposedAction,
    build_response_plan,
    execute_proposed_action,
)
from agent.models.security_alert import SecurityAlert
from agent.models.threat_assessment import ThreatAssessment
from agent.tools.base import Tool
from agent.tools.executor import ToolExecutor
from agent.tools.registry import ToolRegistry


def _alert(**overrides) -> SecurityAlert:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        rule_id="9999",
        rule_description="test alert",
        severity=10,
        agent_id="001",
        agent_name="Kali",
        source_ip="10.0.0.20",
    )
    defaults.update(overrides)
    return SecurityAlert(**defaults)


def _assessment(risk_level: str, threat_type: str = "SSH Brute Force") -> ThreatAssessment:
    return ThreatAssessment(
        threat_type=threat_type,
        risk_level=risk_level,
        confidence=0.9,
        summary="test",
        recommended_actions=["Block source IP"],
    )


# ============================================================
# build_response_plan: deterministic, structured-fields-only
# ============================================================


def test_no_assessment_means_no_plan():
    assert build_response_plan(_alert(), None) == []


def test_low_risk_proposes_nothing():
    plan = build_response_plan(_alert(), _assessment("LOW"))
    assert plan == []


def test_medium_risk_proposes_nothing():
    plan = build_response_plan(_alert(), _assessment("MEDIUM"))
    assert plan == []


def test_high_risk_with_source_ip_proposes_firewall_block():
    plan = build_response_plan(_alert(source_ip="10.0.0.20"), _assessment("HIGH"))

    assert len(plan) == 1
    assert plan[0].tool_name == "FirewallBlockIndicator"
    assert plan[0].tool_parameters == {"indicator": "10.0.0.20"}
    assert plan[0].requires_approval is True


def test_high_risk_without_source_ip_proposes_nothing():
    plan = build_response_plan(_alert(source_ip=None), _assessment("HIGH"))
    assert plan == []


def test_critical_risk_proposes_isolation_and_firewall_block():
    plan = build_response_plan(
        _alert(agent_id="001", source_ip="10.0.0.20"),
        _assessment("CRITICAL"),
    )

    tool_names = {action.tool_name for action in plan}
    assert tool_names == {"WazuhIsolateAgent", "FirewallBlockIndicator"}
    assert all(action.requires_approval for action in plan)


def test_critical_risk_without_agent_id_skips_isolation():
    plan = build_response_plan(
        _alert(agent_id="unknown", source_ip="10.0.0.20"),
        _assessment("CRITICAL"),
    )

    tool_names = {action.tool_name for action in plan}
    assert "WazuhIsolateAgent" not in tool_names
    assert "FirewallBlockIndicator" in tool_names


def test_plan_never_reads_recommended_actions_text():
    """
    The plan must be identical regardless of what the LLM's free
    text says -- only risk_level and alert fields drive it.
    """

    assessment_a = ThreatAssessment(
        threat_type="X",
        risk_level="HIGH",
        confidence=0.9,
        summary="s",
        recommended_actions=["Do absolutely nothing"],
    )
    assessment_b = ThreatAssessment(
        threat_type="X",
        risk_level="HIGH",
        confidence=0.9,
        summary="s",
        recommended_actions=["Isolate the entire network immediately"],
    )

    plan_a = build_response_plan(_alert(), assessment_a)
    plan_b = build_response_plan(_alert(), assessment_b)

    assert plan_a == plan_b


# ============================================================
# execute_proposed_action: still goes through the real guard
# ============================================================


def _build_executor(guard, handler=None) -> tuple[ToolExecutor, MagicMock]:
    handler = handler or MagicMock(return_value={"blocked": True})
    registry = ToolRegistry()
    registry.register(
        Tool(
            name="FirewallBlockIndicator",
            description="test",
            handler=handler,
        )
    )
    executor = ToolExecutor(registry=registry, guard=guard)
    return executor, handler


class AllowGuard:
    def assess(self, *args, **kwargs):
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class _Result:
            decision: str = "ALLOW"
            risk_score: float = 0.0
            matched_attack: str | None = None

        return _Result()


class BlockGuard:
    def assess(self, *args, **kwargs):
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class _Result:
            decision: str = "BLOCK"
            risk_score: float = 1.0
            matched_attack: str = "test"

        return _Result()


def test_approved_action_executes_through_tool_executor():
    executor, handler = _build_executor(AllowGuard())
    action = ProposedAction(
        tool_name="FirewallBlockIndicator",
        tool_parameters={"indicator": "10.0.0.20"},
        reason="test reason",
    )

    result = execute_proposed_action(action, executor, approved_by="analyst_1")

    assert result.status == "EXECUTED"
    handler.assert_called_once_with(indicator="10.0.0.20")


def test_approval_does_not_bypass_the_guard():
    """
    Even a human-approved action still passes through
    ToolMisuseGuard -- approval decides IF it runs, not whether the
    guard is consulted.
    """

    executor, handler = _build_executor(BlockGuard())
    action = ProposedAction(
        tool_name="FirewallBlockIndicator",
        tool_parameters={"indicator": "10.0.0.20"},
        reason="test reason",
    )

    result = execute_proposed_action(action, executor, approved_by="analyst_1")

    assert result.status == "BLOCKED"
    handler.assert_not_called()
