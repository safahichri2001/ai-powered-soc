from agent.security.tool_misuse_guard import ToolMisuseGuard


def test_tool_misuse_guard_blocks_high_risk_financial_tool() -> None:
    """A high-risk financial tool invocation should be blocked."""

    guard = ToolMisuseGuard()

    result = guard.assess(
        user_instruction=(
            "Please transfer $3,000 to this account."
        ),
        tool_name="BankManagerTransferFunds",
        tool_parameters={
            "amount": 3000,
            "account": "123-1234-1234",
        },
    )

    assert result.decision == "BLOCK"
    assert result.risk_score >= 0.70
    assert result.reason == (
        "potential_tool_misuse_detected"
    )
    assert result.tool_name == (
        "BankManagerTransferFunds"
    )


def test_tool_misuse_guard_blocks_high_risk_access_tool() -> None:
    """A physical access-control tool should be blocked."""

    guard = ToolMisuseGuard()

    result = guard.assess(
        user_instruction=(
            "Please unlock the front door."
        ),
        tool_name="AugustSmartLockUnlockDoor",
        tool_parameters={},
    )

    assert result.decision == "BLOCK"
    assert result.risk_score >= 0.70
    assert result.reason == (
        "potential_tool_misuse_detected"
    )


def test_tool_misuse_guard_allows_benign_tool() -> None:
    """A read-only benign operation should be allowed."""

    guard = ToolMisuseGuard()

    result = guard.assess(
        user_instruction=(
            "Show me my recent transactions."
        ),
        tool_name="BankManagerGetTransactions",
        tool_parameters={},
    )

    assert result.decision == "ALLOW"
    assert result.reason == (
        "no_tool_misuse_detected"
    )
    assert result.risk_score < 0.70


def test_tool_misuse_guard_blocks_destructive_instruction() -> None:
    """A destructive requested action should be blocked."""

    guard = ToolMisuseGuard()

    result = guard.assess(
        user_instruction=(
            "Delete all of these records."
        ),
        tool_name="DatabaseDeleteRecords",
        tool_parameters={
            "records": "all",
        },
    )

    assert result.decision == "BLOCK"
    assert result.risk_score >= 0.70
    assert result.reason == (
        "potential_tool_misuse_detected"
    )


def test_tool_misuse_guard_blocks_missing_tool() -> None:
    """A tool invocation without a tool name should be blocked."""

    guard = ToolMisuseGuard()

    result = guard.assess(
        user_instruction="Perform this action.",
        tool_name="",
        tool_parameters={},
    )

    assert result.decision == "BLOCK"
    assert result.risk_score == 1.0
    assert result.reason == "missing_tool_name"