from __future__ import annotations

from agent.security.null_guard import NullGuard


def test_null_guard_always_allows():
    guard = NullGuard()

    result = guard.assess("anything at all")

    assert result.decision == "ALLOW"
    assert result.risk_score == 0.0


def test_null_guard_ignores_arguments():
    guard = NullGuard()

    result = guard.assess("text", top_k=3, extra="ignored")

    assert result.decision == "ALLOW"
