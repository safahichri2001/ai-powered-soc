from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NullGuardResult:
    decision: str = "ALLOW"
    risk_score: float = 0.0
    reason: str = "guard_not_applicable_for_this_input_type"


class NullGuard:
    """
    An always-ALLOW guard for a pipeline stage where a particular
    guard does not apply to the input type it would receive.

    Used in place of SemanticGuard for alert-text analysis (see
    agent/analysis/live_alert_investigator.py): that guard's
    threshold is calibrated for freeform chat text
    (tests/security/calibrate_threshold.py). Calibrating it
    separately against real formatted alert text
    (tests/security/calibrate_alert_semantic_threshold.py) showed
    benign alert scores (max 0.4207) overlap attack alert scores
    (min 0.3421) on this corpus -- no threshold exists that
    separates them without either missing attacks or blocking most
    legitimate alerts. InputGuard's regex layer measured 0% false
    positives / 100% detection on the same alert-text validation
    set (after closing a "disregard the security policy" gap it
    initially missed) and remains the active defense for that path.
    """

    def assess(self, *args, **kwargs) -> NullGuardResult:
        return NullGuardResult()
