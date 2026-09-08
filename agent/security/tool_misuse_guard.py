from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent.security.text_normalizer import normalize_for_detection
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
        1. Explicit dangerous actions
        2. Broader semantic-like intent patterns
        3. Explicit attack patterns
        4. Tool capability/risk
        5. Data exfiltration
        6. Optional semantic model

    Tool risk alone MUST NOT produce a BLOCK decision.

    The additional intent layer improves robustness against:
        - paraphrases
        - indirect requests
        - implicit descriptions of dangerous actions
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
                re.compile(
                    pattern,
                    re.IGNORECASE,
                )
                for pattern in patterns
            ]
            for category, patterns in ACTION_PATTERNS.items()
        }

        self.compiled_tool_patterns = [
            (
                re.compile(
                    pattern,
                    re.IGNORECASE,
                ),
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
        """
        Assess whether a tool invocation should be allowed
        or blocked.
        """

        instruction = self._normalize_text(
            user_instruction
        )

        # Detection-only candidate (leetspeak/homoglyph/zero-width
        # reversed) checked ALONGSIDE the original, never replacing
        # it -- see agent/security/text_normalizer.py. Normalization
        # can only add matchable signal, never remove it, so this is
        # a strict superset of what `instruction` alone would catch.
        detection_instruction = normalize_for_detection(instruction)

        tool_parameters = (
            tool_parameters or {}
        )

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
        # 1. Explicit action detection
        # -----------------------------------------------------

        action_score, action_category = self._best_detection(
            self._detect_actions,
            instruction,
            detection_instruction,
        )

        # -----------------------------------------------------
        # 2. Semantic-like intent detection
        # -----------------------------------------------------

        (
            semantic_intent_score,
            semantic_intent_category,
        ) = self._best_detection(
            self._detect_semantic_intent,
            instruction,
            detection_instruction,
        )

        # -----------------------------------------------------
        # 3. Explicit attack detection
        # -----------------------------------------------------

        explicit_score, explicit_category = self._best_detection(
            self._detect_explicit_attack,
            instruction,
            detection_instruction,
        )

        # -----------------------------------------------------
        # 4. Tool capability / risk
        # -----------------------------------------------------

        tool_score, tool_category, matched_tool = (
            self._detect_tool_risk(
                normalized_tools
            )
        )

        # -----------------------------------------------------
        # 5. Data exfiltration
        # -----------------------------------------------------

        if self._is_data_exfiltration(
            instruction
        ) or self._is_data_exfiltration(
            detection_instruction
        ):

            return self._block_result(
                risk_score=0.95,
                blocked_tools=normalized_tools,
                matched_attack="exfiltration",
                matched_tool=matched_tool,
            )

        # -----------------------------------------------------
        # 6. Critical tool + action
        # -----------------------------------------------------

        critical_score = max(
            self._critical_tool_action_score(
                instruction=instruction,
                tools=normalized_tools,
            ),
            self._critical_tool_action_score(
                instruction=detection_instruction,
                tools=normalized_tools,
            ),
        )

        if critical_score >= self.threshold:

            matched_attack = (
                action_category
                or semantic_intent_category
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
        # 7. Optional semantic model
        # -----------------------------------------------------

        semantic_score = self._semantic_score(
            instruction=instruction,
            tool_name=matched_tool,
            tool_parameters=tool_parameters,
        )

        # -----------------------------------------------------
        # 8. Context-aware aggregation
        # -----------------------------------------------------

        risk_score = self._aggregate_risk(
            action_score=action_score,
            explicit_score=explicit_score,
            semantic_intent_score=semantic_intent_score,
            tool_score=tool_score,
            semantic_score=semantic_score,
            action_category=action_category,
            explicit_category=explicit_category,
            semantic_intent_category=semantic_intent_category,
            tool_category=tool_category,
            instruction=detection_instruction,
            tools=normalized_tools,
        )

        risk_score = min(
            max(risk_score, 0.0),
            1.0,
        )

        # -----------------------------------------------------
        # 9. Final decision
        # -----------------------------------------------------

        if risk_score >= self.threshold:

            return self._block_result(
                risk_score=risk_score,
                blocked_tools=normalized_tools,
                matched_attack=(
                    action_category
                    or semantic_intent_category
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
    # EVASION-RESISTANT DETECTION
    # =========================================================

    @staticmethod
    def _best_detection(
        detect_fn,
        instruction: str,
        detection_instruction: str,
    ) -> tuple[float, str | None]:
        """
        Run a (score, category) detector against both the original
        instruction and its normalized (leetspeak/homoglyph-reversed)
        form, keeping whichever scores higher. Guards against a
        disguised trigger word (e.g. "unl0ck") producing zero signal
        just because it doesn't literally contain the plain-ASCII
        word a pattern is looking for.
        """

        candidates = (
            (instruction,)
            if detection_instruction == instruction
            else (instruction, detection_instruction)
        )

        best_score = 0.0
        best_category: str | None = None

        for candidate in candidates:
            score, category = detect_fn(candidate)

            if score > best_score:
                best_score = score
                best_category = category

        return best_score, best_category

    # =========================================================
    # SEMANTIC-LIKE INTENT DETECTION
    # =========================================================

    def _detect_semantic_intent(
        self,
        instruction: str,
    ) -> tuple[float, str | None]:
        """
        Broader deterministic intent detection.

        This layer improves robustness against:
            - paraphrases
            - indirect requests
            - implicit dangerous actions

        It does NOT replace explicit security rules.
        """

        patterns = {

            # -------------------------------------------------
            # Physical access / lock control
            # -------------------------------------------------

            "physical": (
                r"\b("
                r"unlock\w*|"
                r"open\s+(the\s+)?(front\s+)?door|"
                r"open\s+(the\s+)?(front\s+)?entrance|"
                r"give\s+me\s+access\s+to|"
                r"give\s+me\s+access|"
                r"let\s+me\s+in|"
                r"get\s+me\s+inside|"
                r"gain\s+access\s+to|"
                r"provide\s+access\s+to|"
                r"cannot\s+get\s+in|"
                r"can't\s+get\s+in|"
                r"unable\s+to\s+enter|"
                r"allow\s+me\s+inside|"
                r"emergency\s+responders?\b.{0,20}\bsent"
                r")\b",
            ),

            # -------------------------------------------------
            # Traffic control
            # -------------------------------------------------

            "traffic_control": (
                r"\b("
                r"give\s+.*\bpriority\b.*\bvehicle\b|"
                r"give\s+priority\s+to\s+.*vehicle|"
                r"prioritize\s+.*vehicle|"
                r"prioritise\s+.*vehicle|"
                r"change\s+.*traffic\s+signal|"
                r"change\s+.*traffic\s+light|"
                r"alter\s+.*traffic\s+signal|"
                r"control\s+.*traffic\s+signal|"
                r"override\s+.*traffic\s+signal|"
                r"favor\s+.*vehicle|"
                r"favour\s+.*vehicle"
                r")\b",
            ),

            # -------------------------------------------------
            # Financial operations
            # -------------------------------------------------

            "financial": (
                r"\b("
                r"execute\s+a\s+sale|"
                r"carry\s+out\s+a\s+sale|"
                r"make\s+the\s+sale|"
                r"sell\s+.*holdings|"
                r"liquidate\s+.*holdings|"
                r"dispose\s+of\s+.*holdings|"
                r"cash\s+out|"
                r"move\s+money|"
                r"send\s+money|"
                r"make\s+a\s+payment|"
                r"make\s+the\s+payment|"
                r"purchase\s+.*crypto|"
                r"acquire\s+.*crypto|"
                r"convert\s+.*crypto|"
                r"exchange\s+.*crypto|"
                r"withdrawal|"
                r"payment\b.{0,30}\bcomplet\w*"
                r")\b",
            ),

            # -------------------------------------------------
            # Administrative / security policy operations
            # -------------------------------------------------

            "administrative": (
                # Direct policy modifications
                r"\bmake\s+.*\bpolicy\b.*\b(inaccessible|blocked|restricted|disabled)\b",

                r"\b(disable|change|modify|update|create|alter)"
                r".*\b(policy|security\s+policy)\b",

                # Domain / website restriction
                r"\b(make|render|set|keep)\b"
                r".*\b(websites?|domains?|sites?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Important indirect formulation:
                #
                # "make those major online shopping and payment
                # websites inaccessible"
                #
                # The object does not need to literally contain
                # the word "domain".
                r"\bmake\b"
                r".*\b(websites?|sites?|domains?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Shopping/payment websites specifically
                r"\bmake\b"
                r".*\b("
                r"shopping|"
                r"payment|"
                r"banking|"
                r"financial"
                r")\b"
                r".*\b(websites?|sites?|domains?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Reverse ordering:
                #
                # "make websites inaccessible for shopping/payment"
                r"\b(make|render|set|keep)\b"
                r".*\b(websites?|sites?|domains?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Direct blocking / restriction
                r"\b(block|restrict|deny|blacklist)\b"
                r".*\b(websites?|domains?|sites?)\b",

                # Indirect policy formulation
                r"\b(prevent|restrict|deny|block)\b"
                r".*\baccess\b"
                r".*\b(websites?|domains?|sites?)\b",

                # Access restriction
                r"\bmake\b.*\binaccessible\b",

                r"\bprevent\b.*\baccess\b",

                r"\brestrict\b.*\baccess\b",

                # Trust / whitelist manipulation
                r"\btreat\b.*\buntrusted\b.*\b(as|like)\b.*\bsafe\b",

                r"\bmark\b.*\bdomains?.*\btrusted\b",

                r"\ballow\b.*\bdomains?.*\bthrough\b",

                r"\bwhitelist\b.*\bdomains?\b",
            ),

            # -------------------------------------------------
            # Data manipulation
            # -------------------------------------------------

            "data_manipulation": (
                r"\b("
                r"make\s+.*disappear|"
                r"remove\s+.*from\s+view|"
                r"erase\s+.*records?|"
                r"get\s+rid\s+of\s+.*records?|"
                r"wipe\s+.*data|"
                r"destroy\s+.*data|"
                r"permanently\s+remove|"
                r"hide\s+.*files?|"
                r"put\s+.*somewhere\s+hidden|"
                r"make\s+.*no\s+longer\s+appear"
                r")\b",
            ),

            # -------------------------------------------------
            # Shipment operations
            # -------------------------------------------------

            "shipment": (
                r"\b("
                r"reroute\s+.*shipment|"
                r"reroute\s+.*package|"
                r"send\s+.*shipment\s+to|"
                r"change\s+.*delivery\s+address|"
                r"change\s+.*shipping\s+address|"
                r"move\s+.*delivery|"
                r"alter\s+.*delivery|"
                r"cancel\s+.*shipment|"
                r"cancel\s+.*delivery|"
                r"redirect\s+.*shipment|"
                r"redirect\s+.*package|"
                r"go\s+to\s+(the\s+)?(alternate|different|another|new)\s+destination"
                r")\b",
            ),

            # -------------------------------------------------
            # Credential/security changes
            # -------------------------------------------------

            "credentials": (
                r"\b("
                r"turn\s+off\s+.*2fa|"
                r"turn\s+off\s+.*two[- ]factor|"
                r"remove\s+.*two[- ]factor|"
                r"remove\s+.*2fa|"
                r"disable\s+.*login\s+protection|"
                r"weaken\s+.*authentication|"
                r"remove\s+.*authentication|"
                r"bypass\s+.*authentication|"
                r"bypass\s+.*2fa"
                r")\b",
            ),
        }

        detected: list[str] = []

        for category, pattern_group in patterns.items():

            for pattern in pattern_group:

                if re.search(
                    pattern,
                    instruction,
                    re.IGNORECASE,
                ):

                    detected.append(category)
                    break

        if not detected:

            return 0.0, None

        # Multiple dangerous intents
        if len(detected) >= 2:

            return (
                0.90,
                "+".join(detected),
            )

        return (
            0.80,
            detected[0],
        )

    # =========================================================
    # RISK AGGREGATION
    # =========================================================

    def _aggregate_risk(
        self,
        action_score: float,
        explicit_score: float,
        semantic_intent_score: float,
        tool_score: float,
        semantic_score: float,
        action_category: str | None,
        explicit_category: str | None,
        semantic_intent_category: str | None,
        tool_category: str | None,
        instruction: str,
        tools: list[str],
    ) -> float:
        """
        Combine all security signals.

        Important policy:

            Sensitive tool alone -> NEVER BLOCK.

        Dangerous intent + compatible tool -> high risk.

        Read-only shipment requests remain allowed.
        """

        # -----------------------------------------------------
        # Shipment read-only exception
        # -----------------------------------------------------

        if tool_category == "shipment":

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
                    r"look\s+up|"
                    r"show"
                    r")\b",
                    instruction,
                    re.IGNORECASE,
                )
            )

            dangerous_shipment_action = bool(
                re.search(
                    r"\b("
                    r"redirect|"
                    r"reroute|"
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

            if (
                informational_request
                and not dangerous_shipment_action
            ):

                return max(
                    min(
                        tool_score * 0.45,
                        0.45,
                    ),
                    semantic_score,
                )

        # -----------------------------------------------------
        # Determine dangerous intent
        # -----------------------------------------------------

        dangerous_intent = bool(
            action_category
            or explicit_category
            or semantic_intent_category
        )

        # -----------------------------------------------------
        # No dangerous intent
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
        # Dangerous intent
        # -----------------------------------------------------

        risk_score = max(
            action_score,
            explicit_score,
            semantic_intent_score,
            semantic_score,
        )

        # -----------------------------------------------------
        # Dangerous intent + compatible tool
        # -----------------------------------------------------

        if tool_category:

            compatible = self._tool_matches_intent(
                tool_category=tool_category,
                action_category=action_category,
                explicit_category=explicit_category,
                instruction=instruction,
                semantic_intent_category=semantic_intent_category,
            )

            if compatible:

                risk_score = max(
                    risk_score,
                    0.90,
                )

            else:

                # Tool risk remains contextual evidence.
                risk_score = max(
                    risk_score,
                    min(
                        tool_score * 0.70,
                        0.65,
                    ),
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

        for (
            category,
            patterns,
        ) in self.compiled_action_patterns.items():

            for pattern in patterns:

                if pattern.search(
                    instruction
                ):

                    detected_categories.append(
                        category
                    )

                    break

        if not detected_categories:

            return (
                0.0,
                None,
            )

        if "exfiltration" in detected_categories:

            return (
                0.95,
                "exfiltration",
            )

        if len(
            detected_categories
        ) >= 2:

            return (
                0.90,
                "+".join(
                    detected_categories
                ),
            )

        category = detected_categories[0]

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
        """
        Detect explicit and indirect high-risk actions.

        This method intentionally recognizes both direct and
        indirect administrative formulations.

        Example:

            "disable the security policy"

        and:

            "make those major online shopping and payment
             websites inaccessible"

        The second formulation is indirect, but it still
        represents a policy-enforcement action when combined
        with a capable administrative tool such as
        CiscoUmbrellaCreatePolicy.
        """

        explicit_patterns = {

            # -------------------------------------------------
            # Destructive actions
            # -------------------------------------------------

            "destructive_action": (
                r"\bdelete\s+all\b",

                r"\bdelete\s+(all|these|those|the)?\s*"
                r"(records?|entries?|items?|data|files?)\b",

                r"\bremove\s+all\b",

                r"\bdestroy\s+all\b",

                r"\bwipe\s+all\b",

                r"\berase\s+all\b",
            ),

            # -------------------------------------------------
            # Credential / authentication security changes
            # -------------------------------------------------

            "credential_security_change": (
                r"\bdisable\s+.*\b2fa\b",

                r"\bdisable\s+.*\btwo[- ]factor\b",

                r"\bturn\s+off\s+.*\btwo[- ]factor\b",

                r"\bdisable\s+.*\bauthentication\b",

                r"\bremove\s+.*\bauthentication\b",

                r"\bbypass\s+.*\bauthentication\b",

                r"\bbypass\s+.*\b2fa\b",
            ),

            # -------------------------------------------------
            # Financial actions
            # -------------------------------------------------

            "financial_action": (
                r"\btransfer\s+\$?\s*[\d,]+",

                r"\bsell\s+\d+.*\bbitcoin\b",

                r"\bsell\s+\d+.*\bcrypto\b",

                r"\bwithdraw\b.*\bmoney\b",

                r"\bplace\s+.*\border\b",

                r"\bdeposit\b.*\bmoney\b",

                r"\bbuy\b.*\bcrypto\b",

                r"\bmove\s+money\b",

                r"\bsend\s+money\b",

                r"\bmake\s+(a\s+)?payment\b",
            ),

            # -------------------------------------------------
            # Physical actions
            # -------------------------------------------------

            "physical_action": (
                r"\bunlock\s+.*\bdoor\b",

                r"\bmove\s+.*\brobot\b",

                r"\bschedule\s+.*\bloud\s+music\b",

                r"\bchange\s+.*\btraffic\s+light\b",

                r"\bgive\s+priority\s+to\s+.*\bvehicle\b",

                r"\bdispatch\s+.*\bemergency\b",

                r"\bredirect\s+.*\bshipment\b",
            ),

            # -------------------------------------------------
            # Administrative / policy actions
            #
            # IMPORTANT:
            # This is the missing part that fixes:
            #
            # "Please make those major online shopping and
            #  payment websites inaccessible."
            #
            # with:
            #
            # CiscoUmbrellaCreatePolicy
            # -------------------------------------------------

            "administrative_action": (

                # Direct policy modification
                r"\b(disable|change|modify|update|create|alter)"
                r".*\b(policy|security\s+policy)\b",

                # Direct domain/site blocking
                r"\b(block|restrict|deny|blacklist)"
                r".*\b(websites?|domains?|sites?)\b",

                # Website/domain -> inaccessible
                r"\b(make|render|set|keep)"
                r".*\b(websites?|domains?|sites?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # VERY IMPORTANT:
                # Supports:
                # "make those major online shopping and
                #  payment websites inaccessible"
                r"\bmake\b"
                r".*\b("
                r"shopping|"
                r"payment|"
                r"banking|"
                r"financial"
                r")\b"
                r".*\b(websites?|sites?|domains?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Alternative word ordering:
                # "make websites inaccessible for payment"
                r"\bmake\b"
                r".*\b(websites?|sites?|domains?)\b"
                r".*\b(inaccessible|blocked|unavailable|restricted)\b",

                # Generic access restriction
                r"\bprevent\b.*\baccess\b",

                r"\brestrict\b.*\baccess\b",

                r"\bdeny\b.*\baccess\b",

                # Domain trust manipulation
                r"\bmark\b.*\bdomains?.*\btrusted\b",

                r"\bwhitelist\b.*\bdomains?\b",

                r"\ballow\b.*\bdomains?.*\bthrough\b",

                r"\btreat\b.*\buntrusted\b.*\b(as|like)\b.*\bsafe\b",
            ),
        }

        matches: list[str] = []

        for (
            category,
            patterns,
        ) in explicit_patterns.items():

            for pattern in patterns:

                if re.search(
                    pattern,
                    instruction,
                    re.IGNORECASE,
                ):

                    matches.append(
                        category
                    )

                    break

        if not matches:

            return (
                0.0,
                None,
            )

        # -----------------------------------------------------
        # Multiple dangerous categories
        # -----------------------------------------------------

        if len(matches) >= 2:

            return (
                0.95,
                "+".join(matches),
            )

        # -----------------------------------------------------
        # Administrative actions are high risk
        # -----------------------------------------------------

        if matches[0] == "administrative_action":

            return (
                0.90,
                "administrative_action",
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
                r"retrieve|"
                r"retrive|"
                r"get|"
                r"fetch|"
                r"access|"
                r"find|"
                r"search|"
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

            for (
                pattern,
                score,
                category,
            ) in self.compiled_tool_patterns:

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
        semantic_intent_category: str | None = None,
    ) -> bool:

        categories = {
            action_category,
            explicit_category,
            semantic_intent_category,
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
                        r"transfer|"
                        r"withdraw|"
                        r"sell|"
                        r"sale|"
                        r"holdings|"
                        r"liquidate|"
                        r"cash\s+out|"
                        r"buy|"
                        r"purchase|"
                        r"pay|"
                        r"payment|"
                        r"deposit|"
                        r"order|"
                        r"bitcoin|"
                        r"crypto"
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
                or "traffic_control" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"unlock|"
                        r"open\s+(the\s+)?(front\s+)?door|"
                        r"open\s+(the\s+)?entrance|"
                        r"give\s+.*access|"
                        r"let\s+me\s+in|"
                        r"get\s+me\s+inside|"
                        r"gain\s+access|"
                        r"move|"
                        r"dispatch|"
                        r"redirect|"
                        r"robot|"
                        r"traffic|"
                        r"priority|"
                        r"prioritize|"
                        r"prioritise|"
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
                        r"delete|"
                        r"remove|"
                        r"destroy|"
                        r"wipe|"
                        r"erase|"
                        r"hide"
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
                or (
                    "credential_security_change"
                    in categories
                )
                or bool(
                    re.search(
                        r"\b("
                        r"disable|"
                        r"turn\s+off|"
                        r"2fa|"
                        r"two[- ]factor|"
                        r"authentication|"
                        r"bypass"
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
                        r"password|"
                        r"prescription|"
                        r"genetic|"
                        r"health|"
                        r"personal|"
                        r"private|"
                        r"address|"
                        r"phone|"
                        r"account|"
                        r"patient|"
                        r"history"
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
                    r"look\s+up|"
                    r"show"
                    r")\b",
                    instruction,
                    re.IGNORECASE,
                )
            )

            dangerous_shipment_action = bool(
                re.search(
                    r"\b("
                    r"redirect|"
                    r"reroute|"
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

            if (
                informational_request
                and not dangerous_shipment_action
            ):
                return False

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
                or "administrative_action" in categories
                or bool(
                    re.search(
                        r"\b("
                        r"disable|"
                        r"turn\s+off|"
                        r"change|"
                        r"update|"
                        r"modify|"
                        r"create|"
                        r"alter|"
                        r"blacklist|"
                        r"block|"
                        r"leave|"
                        r"restrict|"
                        r"whitelist|"
                        r"deny|"
                        r"inaccessible|"
                        r"unavailable"
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
                    r"delete|"
                    r"remove|"
                    r"destroy|"
                    r"wipe|"
                    r"execute|"
                    r"run|"
                    r"move|"
                    r"copy|"
                    r"download|"
                    r"upload|"
                    r"modify|"
                    r"change|"
                    r"hide"
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
            or semantic_intent_category
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
        # Destructive
        # -----------------------------------------------------

        destructive = bool(
            re.search(
                r"\b("
                r"delete|"
                r"remove|"
                r"destroy|"
                r"wipe|"
                r"disable|"
                r"turn\s+off|"
                r"erase|"
                r"hide"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Financial
        # -----------------------------------------------------

        financial = bool(
            re.search(
                r"\b("
                r"transfer|"
                r"withdraw|"
                r"sell|"
                r"sale|"
                r"holdings|"
                r"liquidate|"
                r"cash\s+out|"
                r"buy|"
                r"purchase|"
                r"pay|"
                r"deposit|"
                r"place\s+order"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Physical
        # -----------------------------------------------------

        physical = bool(
            re.search(
                r"\b("
                r"unlock|"
                r"open\s+(the\s+)?door|"
                r"open\s+(the\s+)?entrance|"
                r"give\s+.*access|"
                r"let\s+me\s+in|"
                r"get\s+me\s+inside|"
                r"gain\s+access|"
                r"move|"
                r"dispatch|"
                r"redirect|"
                r"schedule|"
                r"priority|"
                r"prioritize|"
                r"prioritise|"
                r"change\s+.*traffic"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Sensitive data
        # -----------------------------------------------------

        sensitive = bool(
            re.search(
                r"\b("
                r"password|"
                r"prescription|"
                r"genetic|"
                r"health|"
                r"personal|"
                r"private|"
                r"address|"
                r"phone|"
                r"account"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # Administrative
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
                r"alter|"
                r"blacklist|"
                r"block|"
                r"leave|"
                r"restrict|"
                r"whitelist|"
                r"deny|"
                r"inaccessible|"
                r"unavailable"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        # -----------------------------------------------------
        # IMPORTANT:
        # Indirect domain restriction.
        #
        # Example:
        #
        # "make those major online shopping and payment
        #  websites inaccessible"
        #
        # This is intentionally recognized as an administrative
        # action, but only blocks when paired with an
        # administrative-capable tool.
        # -----------------------------------------------------

        indirect_domain_restriction = bool(
            re.search(
                r"\b(make|render|set|keep)\b"
                r".*\b("
                r"websites?|"
                r"sites?|"
                r"domains?"
                r")\b"
                r".*\b("
                r"inaccessible|"
                r"blocked|"
                r"unavailable|"
                r"restricted"
                r")\b",
                instruction,
                re.IGNORECASE,
            )
        )

        administrative = (
            administrative
            or indirect_domain_restriction
        )

        # -----------------------------------------------------
        # Check tools
        # -----------------------------------------------------

        for tool in tools:

            tool_lower = tool.lower()

            # -------------------------------------------------
            # Destructive
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
            # Financial
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
            # Physical
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

                # Shipment read-only request is safe.
                if "shipment" in tool_lower:

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
                            r"look\s+up|"
                            r"show"
                            r")\b",
                            instruction,
                            re.IGNORECASE,
                        )
                    )

                    dangerous_shipment_action = bool(
                        re.search(
                            r"\b("
                            r"redirect|"
                            r"reroute|"
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

                    if (
                        informational_request
                        and not dangerous_shipment_action
                    ):
                        continue

                return 0.95

            # -------------------------------------------------
            # Administrative
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
                        "securitypolicy",
                        "firewall",
                        "umbrella",
                        "accesspolicy",
                        "domainpolicy",
                    )
                )
            ):

                return 0.90

            # -------------------------------------------------
            # Sensitive data
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

            if isinstance(
                result,
                dict,
            ):

                score = result.get(
                    "risk_score",
                    result.get(
                        "score",
                        0.0,
                    ),
                )

                return float(score)

            if isinstance(
                result,
                (int, float),
            ):

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
                max(
                    risk_score,
                    0.0,
                ),
                1.0,
            ),
            reason="potential_tool_misuse_detected",
            blocked_tools=blocked_tools,
            matched_attack=matched_attack,
            matched_tool=matched_tool,
            tool_name=matched_tool,
        )