from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent.security.tool_misuse_rules import (
    ACTION_PATTERNS,
    TOOL_RISK_PATTERNS,
)


@dataclass
class ToolMisuseGuardResult:
    decision: str
    risk_score: float
    reason: str
    blocked_tools: list[str]
    matched_attack: str | None = None
    matched_tool: str | None = None
    tool_name: str | None = None


class ToolMisuseGuard:
    """
    Deterministic tool-misuse guard.

    Security principle:
        A sensitive/high-risk tool alone is NOT sufficient to block.

    The guard combines:
        1. Dangerous user intent
        2. Explicit attack patterns
        3. Tool capability/risk
        4. Data exfiltration
        5. Optional semantic model

    A tool-risk rule acts as contextual evidence. It does not
    automatically turn a benign request into a BLOCK decision.
    """

    THRESHOLD = 0.70

    def __init__(
        self,
        threshold: float = THRESHOLD,
        model: Any | None = None,
    ) -> None:
        self.threshold = threshold
        self.model = model

        self.compiled_action_patterns = {
            category: [
                re.compile(pattern, re.IGNORECASE)
                for pattern in patterns
            ]
            for category, patterns in ACTION_PATTERNS.items()
        }

        self.compiled_tool_patterns = [
            (
                re.compile(pattern, re.IGNORECASE),
                score,
                category,
            )
            for pattern, score, category in TOOL_RISK_PATTERNS
        ]

    # =========================================================
    # PUBLIC API
    # =========================================================

    def assess(
        self,
        user_instruction: str,
        tool_name: str | None = None,
        tool_parameters: dict[str, Any] | None = None,
        tools: list[str] | None = None,
    ) -> ToolMisuseGuardResult:

        instruction = self._normalize_text(user_instruction)

        tool_parameters = tool_parameters or {}

        normalized_tools = self._normalize_tools(
            tool_name=tool_name,
            tools=tools,
        )

        # -----------------------------------------------------
        # 0. Missing tool
        # -----------------------------------------------------

        if not normalized_tools:
            return ToolMisuseGuardResult(
               decision="BLOCK",
        risk_score=1.0,
        reason="missing_tool_name",
        blocked_tools=[],
        matched_attack="missing_tool",
        matched_tool=None,
        tool_name=None,
            )

        # -----------------------------------------------------
        # 1. Dangerous action detection
        # -----------------------------------------------------

        action_score, action_category = self._detect_actions(
            instruction
        )

        # -----------------------------------------------------
        # 2. Explicit attack detection
        # -----------------------------------------------------

        explicit_score, explicit_category = (
            self._detect_explicit_attack(
                instruction
            )
        )

        # -----------------------------------------------------
        # 3. Tool capability/risk
        #
        # IMPORTANT:
        # Tool risk alone MUST NOT cause BLOCK.
        # -----------------------------------------------------

        tool_score, tool_category, matched_tool = (
            self._detect_tool_risk(
                normalized_tools
            )
        )

        # -----------------------------------------------------
        # 4. Data exfiltration
        #
        # Retrieval + transmission + external destination
        # is considered high risk independently of the model.
        # -----------------------------------------------------

        if self._is_data_exfiltration(instruction):
            return self._block_result(
                risk_score=0.95,
                blocked_tools=normalized_tools,
                matched_attack="exfiltration",
                matched_tool=matched_tool,
            )

        # -----------------------------------------------------
        # 5. Critical combination:
        # dangerous instruction + capable tool
        # -----------------------------------------------------

        critical_score = self._critical_tool_action_score(
            instruction=instruction,
            tools=normalized_tools,
        )

        if critical_score >= self.threshold:
            matched_attack = (
                action_category
                or explicit_category
                or tool_category
                or "high_risk_tool_action"
            )

            return self._block_result(
                risk_score=critical_score,
                blocked_tools=normalized_tools,
                matched_attack=matched_attack,
                matched_tool=matched_tool,
            )

        # -----------------------------------------------------
        # 6. Semantic/model score
        # -----------------------------------------------------

        semantic_score = self._semantic_score(
            instruction=instruction,
            tool_name=matched_tool,
            tool_parameters=tool_parameters,
        )

        # -----------------------------------------------------
        # 7. Context-aware aggregation
        # -----------------------------------------------------

        risk_score = self._aggregate_risk(
            action_score=action_score,
            explicit_score=explicit_score,
            tool_score=tool_score,
            semantic_score=semantic_score,
            action_category=action_category,
            explicit_category=explicit_category,
            tool_category=tool_category,
            instruction=instruction,
            tools=normalized_tools,
        )

        risk_score = min(
            max(risk_score, 0.0),
            1.0,
        )

        # -----------------------------------------------------
        # 8. Final decision
        # -----------------------------------------------------

        if risk_score >= self.threshold:
            return self._block_result(
                risk_score=risk_score,
                blocked_tools=normalized_tools,
                matched_attack=(
                    action_category
                    or explicit_category
                    or tool_category
                ),
                matched_tool=matched_tool,
            )

        return ToolMisuseGuardResult(
            decision="ALLOW",
            risk_score=risk_score,
            reason="no_tool_misuse_detected",
            blocked_tools=[],
            matched_attack=None,
            matched_tool=matched_tool,
            tool_name=(
                tool_name
                if tool_name
                else matched_tool
            ),
        )

    # =========================================================
    # RISK AGGREGATION
    # =========================================================

    def _aggregate_risk(
        self,
        action_score: float,
        explicit_score: float,
        tool_score: float,
        semantic_score: float,
        action_category: str | None,
        explicit_category: str | None,
        tool_category: str | None,
        instruction: str,
        tools: list[str],
    ) -> float:
        """
        Combine signals without allowing tool identity alone
        to produce a BLOCK.

        Important policy:
            tool_score alone -> capped below threshold

        Example:
            BinanceWithdraw
            + "show me available information"

            => tool score may be high internally,
               but final risk remains < 0.70.

        A dangerous action + compatible tool can reach >= 0.70.
        """

        # -----------------------------------------------------
        # No dangerous intent:
        # tool risk is only contextual evidence.
        # -----------------------------------------------------

        dangerous_intent = bool(
            action_category
            or explicit_category
        )

        # -----------------------------------------------------
        # Completely benign-looking request.
        #
        # Do not allow tool risk to cross the BLOCK threshold.
        # -----------------------------------------------------

        if not dangerous_intent:
            contextual_tool_score = min(
                tool_score * 0.45,
                0.45,
            )

            return max(
                contextual_tool_score,
                semantic_score,
            )

        # -----------------------------------------------------
        # Explicit dangerous action.
        # -----------------------------------------------------

        risk_score = max(
            action_score,
            explicit_score,
            semantic_score,
        )

        # -----------------------------------------------------
        # Dangerous action + compatible tool.
        # -----------------------------------------------------

        if tool_category:
            compatible = self._tool_matches_intent(
                tool_category=tool_category,
                action_category=action_category,
                explicit_category=explicit_category,
                instruction=instruction,
            )

            if compatible:
                risk_score = max(
                    risk_score,
                    0.90,
                )
            else:
                # Tool is sensitive, but does not clearly
                # correspond to the dangerous action.
                risk_score = max(
                    risk_score,
                    min(tool_score * 0.70, 0.65),
                )

        return risk_score

    # =========================================================
    # ACTION DETECTION
    # =========================================================

    def _detect_actions(
        self,
        instruction: str,
    ) -> tuple[float, str | None]:

        detected_categories: list[str] = []

        for category, patterns in (
            self.compiled_action_patterns.items()
        ):
            for pattern in patterns:
                if pattern.search(instruction):
                    detected_categories.append(category)
                    break

        if not detected_categories:
            return 0.0, None

        # -----------------------------------------------------
        # Exfiltration
        # -----------------------------------------------------

        if "exfiltration" in detected_categories:
            return (
                0.95,
                "exfiltration",
            )

        # -----------------------------------------------------
        # Multiple categories
        # -----------------------------------------------------

        if len(detected_categories) >= 2:
            return (
                0.90,
                "+".join(detected_categories),
            )

        category = detected_categories[0]

        # -----------------------------------------------------
        # High-risk categories
        # -----------------------------------------------------

        if category in {
            "financial",
            "physical",
            "administrative",
            "sensitive_data",
            "shipment",
            "autofill",
            "credentials",
            "data_manipulation",
        }:
            return (
                0.75,
                category,
            )

        return (
            0.70,
            category,
        )

    # =========================================================
    # EXPLICIT ATTACK DETECTION
    # =========================================================

    def _detect_explicit_attack(
        self,
        instruction: str,
    ) -> tuple[float, str | None]:

        explicit_patterns = {
            "destructive_action": (
                r"\bdelete\s+all\b",
                r"\bdelete\s+(all|these|those|the)?\s*"
                r"(records?|entries?|items?|data|files?)\b",
                r"\bremove\s+all\b",
                r"\bdestroy\s+all\b",
                r"\bwipe\s+all\b",
            ),

            "credential_security_change": (
                r"\bdisable\s+.*\b2fa\b",
                r"\bdisable\s+.*\btwo[- ]factor\b",
                r"\bturn\s+off\s+.*\btwo[- ]factor\b",
                r"\bdisable\s+.*\bauthentication\b",
            ),

            "financial_action": (
                r"\btransfer\s+\$?\s*[\d,]+",
                r"\bsell\s+\d+.*\bbitcoin\b",
                r"\bsell\s+\d+.*\bcrypto\b",
                r"\bwithdraw\b.*\bmoney\b",
                r"\bplace\s+.*\border\b",
                r"\bdeposit\b.*\bmoney\b",
                r"\bbuy\b.*\bcrypto\b",
            ),

            "physical_action": (
                r"\bunlock\s+.*\bdoor\b",
                r"\bmove\s+.*\brobot\b",
                r"\bschedule\s+.*\bloud\s+music\b",
                r"\bchange\s+.*\btraffic\s+light\b",
                r"\bgive\s+priority\s+to\s+.*\bvehicle\b",
                r"\bdispatch\s+.*\bemergency\b",
                r"\bredirect\s+.*\bshipment\b",
            ),
        }

        matches: list[str] = []

        for category, patterns in (
            explicit_patterns.items()
        ):
            for pattern in patterns:
                if re.search(
                    pattern,
                    instruction,
                    re.IGNORECASE,
                ):
                    matches.append(category)
                    break

        if not matches:
            return 0.0, None

        if len(matches) >= 2:
            return (
                0.95,
                "+".join(matches),
            )

        return (
            0.90,
            matches[0],
        )

    # =========================================================
    # DATA EXFILTRATION
    # =========================================================

    def _is_data_exfiltration(
        self,
        instruction: str,
    ) -> bool:

        retrieval = bool(
            re.search(
                r"\b("
                r"retrieve|retrive|"
                r"get|fetch|"
                r"access|"
                r"find|search|"
                r"download|"
                r"view|"
                r"list|"
                r"obtain|"
                r"extract|"
                r"collect"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        transmission = bool(
            re.search(
                r"\b("
                r"email|"
                r"send|"
                r"forward|"
                r"share|"
                r"export|"
                r"transmit"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        external_destination = bool(
            re.search(
                r"("
                r"[\w.+-]+@[\w\.-]+\.[a-zA-Z]{2,}"
                r"|"
                r"\bto\s+my\s+alternate\s+email\b"
                r"|"
                r"\bto\s+another\s+email\b"
                r"|"
                r"\bto\s+an?\s+external\b"
                r"|"
                r"\bto\s+someone\s+else\b"
                r")",
                instruction,
                re.IGNORECASE,
            )
        )

        return (
            retrieval
            and transmission
            and external_destination
        )

    # =========================================================
    # TOOL RISK
    # =========================================================

    def _detect_tool_risk(
        self,
        tools: list[str],
    ) -> tuple[
        float,
        str | None,
        str | None,
    ]:

        best_score = 0.0
        best_category: str | None = None
        best_tool: str | None = None

        for tool in tools:
            for pattern, score, category in (
                self.compiled_tool_patterns
            ):
                if pattern.search(tool):
                    if score > best_score:
                        best_score = score
                        best_category = category
                        best_tool = tool

        return (
            best_score,
            best_category,
            best_tool,
        )

    # =========================================================
    # TOOL / INTENT COMPATIBILITY
    # =========================================================

    def _tool_matches_intent(
        self,
        tool_category: str,
        action_category: str | None,
        explicit_category: str | None,
        instruction: str,
    ) -> bool:
        """
        Determine whether the dangerous instruction is actually
        compatible with the capability of the selected tool.
        """

        categories = {
            action_category,
            explicit_category,
        }

        categories.discard(None)

        # -----------------------------------------------------
        # Financial
        # -----------------------------------------------------

        if tool_category in {
            "financial",
            "financial_data",
        }:
            return (
                "financial" in categories
                or "financial_action" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"transfer|withdraw|sell|buy|"
                        r"purchase|pay|deposit|"
                        r"order|bitcoin|crypto"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Physical
        # -----------------------------------------------------

        if tool_category == "physical":
            return (
                "physical" in categories
                or "physical_action" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"unlock|lock|move|dispatch|"
                        r"redirect|robot|traffic|"
                        r"schedule"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Destructive
        # -----------------------------------------------------

        if tool_category == "destructive":
            return (
                "data_manipulation" in categories
                or "destructive_action" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"delete|remove|destroy|wipe"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Credential security
        # -----------------------------------------------------

        if tool_category == "credential_security":
            return (
                "credentials" in categories
                or "credential_security_change"
                in categories
                or bool(
                    re.search(
                        r"\b("
                        r"disable|turn\s+off|"
                        r"2fa|two[- ]factor|"
                        r"authentication"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Sensitive data
        # -----------------------------------------------------

        if tool_category in {
            "sensitive_data",
            "credentials",
            "financial_data",
            "shipment_data",
            "data_access",
        }:
            return (
                "sensitive_data" in categories
                or "credentials" in categories
                or "financial_data" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"password|prescription|genetic|"
                        r"health|personal|private|"
                        r"address|phone|account|"
                        r"patient|history"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Shipment
        # -----------------------------------------------------

        if tool_category == "shipment":
            """
            IMPORTANT FIX:

            A shipment-related tool may be used for harmless
            information retrieval.

            Example:

                "Please search for the shipment information."

            This is a read/search operation and must NOT be
            treated as a dangerous shipment action.

            Dangerous shipment operations remain detectable:

                - redirect shipment
                - reschedule shipment
                - cancel shipment
                - ship/send/deliver shipment
                - modify/change/update shipment
                - change shipment address
            """

            informational_request = bool(
                re.search(
                    r"\b("
                    r"search|"
                    r"find|"
                    r"retrieve|"
                    r"get|"
                    r"fetch|"
                    r"view|"
                    r"list|"
                    r"check|"
                    r"look\s+up"
                    r")\b",
                    instruction,
                    re.IGNORECASE,
                )
            )

            dangerous_shipment_action = bool(
                re.search(
                    r"\b("
                    r"redirect|"
                    r"reschedule|"
                    r"cancel|"
                    r"ship|"
                    r"send|"
                    r"deliver|"
                    r"modify|"
                    r"change|"
                    r"update|"
                    r"address"
                    r")\b",
                    instruction,
                    re.IGNORECASE,
                )
            )

            # Pure information retrieval is benign.
            if informational_request and not dangerous_shipment_action:
                return False

            # Explicit shipment action remains dangerous.
            return (
                "shipment" in categories
                or dangerous_shipment_action
            )

        # -----------------------------------------------------
        # Administrative
        # -----------------------------------------------------

        if tool_category == "administrative":
            return (
                "administrative" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"disable|"
                        r"turn\s+off|"
                        r"change|"
                        r"update|"
                        r"modify|"
                        r"create|"
                        r"blacklist|"
                        r"block|"
                        r"leave"
                        r")\b",
                        instruction,
                        re.IGNORECASE,
                    )
                )
            )

        # -----------------------------------------------------
        # Command execution
        # -----------------------------------------------------

        if tool_category == "command_execution":
            return bool(
                re.search(
                    r"\b("
                    r"delete|remove|destroy|wipe|"
                    r"execute|run|move|copy|"
                    r"download|upload|"
                    r"modify|change"
                    r")\b",
                    instruction,
                    re.IGNORECASE,
                )
            )

        # -----------------------------------------------------
        # Generic fallback
        # -----------------------------------------------------

        return bool(
            action_category
            or explicit_category
        )

    # =========================================================
    # CRITICAL TOOL + ACTION
    # =========================================================

    def _critical_tool_action_score(
        self,
        instruction: str,
        tools: list[str],
    ) -> float:

        if not tools:
            return 0.0

        # -----------------------------------------------------
        # Destructive actions
        # -----------------------------------------------------

        destructive = bool(
            re.search(
                r"\b("
                r"delete|remove|destroy|wipe|"
                r"disable|turn\s+off"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Financial actions
        # -----------------------------------------------------

        financial = bool(
            re.search(
                r"\b("
                r"transfer|withdraw|sell|"
                r"buy|purchase|pay|"
                r"deposit|place\s+order"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Physical actions
        # -----------------------------------------------------

        physical = bool(
            re.search(
                r"\b("
                r"unlock|lock|move|dispatch|"
                r"redirect|schedule|change"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Sensitive-data actions
        # -----------------------------------------------------

        sensitive = bool(
            re.search(
                r"\b("
                r"password|prescription|genetic|"
                r"health|personal|private|"
                r"address|phone|account"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Administrative actions
        # -----------------------------------------------------

        administrative = bool(
            re.search(
                r"\b("
                r"disable|"
                r"turn\s+off|"
                r"change|"
                r"update|"
                r"modify|"
                r"create|"
                r"blacklist|"
                r"block|"
                r"leave"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        for tool in tools:
            tool_lower = tool.lower()

            # -------------------------------------------------
            # Destructive tools
            # -------------------------------------------------

            if (
                destructive
                and any(
                    word in tool_lower
                    for word in (
                        "delete",
                        "remove",
                        "destroy",
                        "disable",
                        "update",
                    )
                )
            ):
                return 0.95

            # -------------------------------------------------
            # Financial tools
            # -------------------------------------------------

            if (
                financial
                and any(
                    word in tool_lower
                    for word in (
                        "transfer",
                        "withdraw",
                        "placeorder",
                        "paybill",
                        "deposit",
                        "buy",
                        "sell",
                    )
                )
            ):
                return 0.95

            # -------------------------------------------------
            # Physical-control tools
            # -------------------------------------------------

            if (
                physical
                and any(
                    word in tool_lower
                    for word in (
                        "unlock",
                        "dispatch",
                        "robot",
                        "traffic",
                        "scheduledevice",
                        "shipment",
                        "shipmanager",
                    )
                )
            ):
                return 0.95

            # -------------------------------------------------
            # Administrative-control tools
            # -------------------------------------------------

            if (
                administrative
                and any(
                    word in tool_lower
                    for word in (
                        "createpolicy",
                        "updatepolicy",
                        "leavechannel",
                        "disabletwofactor",
                    )
                )
            ):
                return 0.90

            # -------------------------------------------------
            # Sensitive-data tools
            # -------------------------------------------------

            if (
                sensitive
                and any(
                    word in tool_lower
                    for word in (
                        "password",
                        "prescription",
                        "genetic",
                        "patient",
                        "personal",
                        "address",
                        "searchhistory",
                        "userdata",
                        "userdetails",
                        "phone",
                        "accountinformation",
                        "savedaddresses",
                        "savedpayment",
                    )
                )
            ):
                return 0.85

        return 0.0

    # =========================================================
    # SEMANTIC MODEL
    # =========================================================

    def _semantic_score(
        self,
        instruction: str,
        tool_name: str | None,
        tool_parameters: dict[str, Any],
    ) -> float:

        if self.model is None:
            return 0.0

        try:
            result = self.model.predict(
                instruction=instruction,
                tool_name=tool_name,
                tool_parameters=tool_parameters,
            )

            if isinstance(result, dict):
                score = result.get(
                    "risk_score",
                    result.get("score", 0.0),
                )

                return float(score)

            if isinstance(result, (int, float)):
                return float(result)

        except Exception:
            return 0.0

        return 0.0

    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def _normalize_text(
        text: str | None,
    ) -> str:

        if not text:
            return ""

        text = str(text)

        text = re.sub(
            r"\s+",
            " ",
            text,
        )

        return text.strip()

    @staticmethod
    def _normalize_tools(
        tool_name: str | None = None,
        tools: list[str] | None = None,
    ) -> list[str]:

        result: list[str] = []

        if tool_name:
            result.append(
                str(tool_name)
            )

        if tools:
            result.extend(
                str(tool)
                for tool in tools
                if tool
            )

        seen: set[str] = set()
        normalized: list[str] = []

        for tool in result:
            if tool not in seen:
                seen.add(tool)
                normalized.append(tool)

        return normalized

    @staticmethod
    def _block_result(
        risk_score: float,
        blocked_tools: list[str],
        matched_attack: str | None,
        matched_tool: str | None,
    ) -> ToolMisuseGuardResult:

        return ToolMisuseGuardResult(
            decision="BLOCK",
            risk_score=min(
                max(risk_score, 0.0),
                1.0,
            ),
            reason="potential_tool_misuse_detected",
            blocked_tools=blocked_tools,
            matched_attack=matched_attack,
            matched_tool=matched_tool,
            tool_name=matched_tool,
        )