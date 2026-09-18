from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.analysis.soar_playbook import ProposedAction, build_response_plan
from agent.analysis.threat_assessment_parser import parse_threat_assessment
from agent.integrations.wazuh_client import WazuhIndexerClient
from agent.llm.ollama_client import OllamaClient
from agent.models.security_alert import SecurityAlert
from agent.models.threat_assessment import ThreatAssessment
from agent.preprocessing.formatter import format_alert_for_ai
from agent.preprocessing.normalizer import normalize_wazuh_alert
from agent.prompts.threat_assessment_prompt import build_threat_assessment_prompt
from agent.security.input_guard import InputGuard
from agent.security.null_guard import NullGuard
from agent.tools.executor import ToolExecutor
from rag.pipeline import RAGPipeline
from rag.retrieval.retriever import Retriever

HIGH_SEVERITY_THRESHOLD = 7  # Wazuh's own "high" tier starts at level 7.


def build_alert_analysis_pipeline(
    retriever: Retriever,
    llm: Any | None = None,
) -> RAGPipeline:
    """
    Build a RAGPipeline configured for analyzing formatted alert
    text rather than freeform chat queries.

    SemanticGuard is deliberately replaced with NullGuard here --
    see agent/security/null_guard.py for why: calibrated against
    real alert text, its chat-tuned embedding similarity cannot
    separate benign alerts from injected ones (the score ranges
    overlap). InputGuard stays active and is the layer actually
    carrying detection for this path.
    """

    return RAGPipeline(
        retriever=retriever,
        llm=llm or OllamaClient(),
        input_guard=InputGuard(),
        semantic_guard=NullGuard(),
        prompt_builder=build_threat_assessment_prompt,
    )


class LiveAlertInvestigator:
    """
    Pulls real alerts from the Wazuh Indexer and runs each one
    through the guarded RAG pipeline, so the LLM analyst reasons
    over live security events instead of only manually typed
    queries.

    Note that a formatted alert becomes the RAG pipeline's "query",
    which means input_guard runs against it exactly as it would a
    user question. This is deliberate: a field an attacker controls
    (e.g. an SSH username, a User-Agent header) can end up inside a
    Wazuh alert and therefore inside the text handed to the LLM --
    the same guard that catches direct prompt injection also catches
    it arriving this way. Build `rag_pipeline` with
    `build_alert_analysis_pipeline()` above rather than constructing
    RAGPipeline directly, so this path doesn't silently pick up the
    chat-tuned SemanticGuard.

    If `tool_executor` is provided, each alert is enriched with a
    small, fixed set of *read-only* lookups (IP reputation, agent
    status) before analysis -- run through ToolExecutor, so they're
    still guarded by ToolMisuseGuard and still audited, exactly like
    any other tool call. This is deliberately narrow: it never lets
    the LLM's output choose which tool to call or with what
    parameters (parsing a model's free text as a command is its own
    attack surface), and it never auto-executes a state-changing
    action. A state-changing recommendation only ever appears as
    text in the analysis for a human to act on separately, through
    the same guarded ToolExecutor, by hand.

    Each result also carries a `threat_assessment`: a structured
    (threat_type, risk_level, confidence, recommended_actions)
    ThreatAssessment parsed out of the LLM's response via
    build_threat_assessment_prompt, or None if parsing failed or the
    alert was blocked. This is the "decision engine" piece of a
    SIEM -> AI -> SOAR pipeline -- what would let a future playbook
    branch on risk_level instead of a human re-reading prose. Parsing
    failure degrades gracefully rather than raising: the free-text
    `analysis["response"]` is always still there as a fallback.

    Each result also carries a `response_plan`: a list of
    ProposedAction from agent/analysis/soar_playbook.py, built only
    from `risk_level` and fixed alert fields (never from the LLM's
    free-text recommended_actions). Every proposed action requires
    human approval -- nothing in this class executes one. Use
    execute_proposed_action() separately, after a human has reviewed
    the plan, to actually run an approved action through
    ToolExecutor.
    """

    def __init__(
        self,
        indexer: WazuhIndexerClient | None = None,
        rag_pipeline: RAGPipeline | None = None,
        tool_executor: ToolExecutor | None = None,
        state_path: str | Path = "logs/alert_investigator_state.json",
        analysis_log_path: str | Path = "logs/alert_analysis_log.jsonl",
    ) -> None:
        if rag_pipeline is None:
            raise ValueError(
                "LiveAlertInvestigator requires a RAGPipeline instance."
            )

        self.indexer = indexer or WazuhIndexerClient()
        self.rag_pipeline = rag_pipeline
        self.tool_executor = tool_executor

        self.state_path = Path(state_path)
        self.analysis_log_path = Path(analysis_log_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.analysis_log_path.parent.mkdir(parents=True, exist_ok=True)

    def investigate_recent(
        self,
        limit: int = 5,
        query: str = "",
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Fetch the most recent alerts and analyze each one, newest
        first. Does not touch the watermark -- calling this twice
        re-analyzes the same alerts if nothing new has arrived. For
        repeated/scheduled polling, use investigate_new() instead.
        """

        raw_alerts = self.indexer.search_alerts(query=query, limit=limit)
        return self._investigate(raw_alerts, top_k=top_k)

    def investigate_new(
        self,
        limit: int = 50,
        query: str = "",
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Fetch and analyze only alerts newer than the last call's
        watermark (persisted in `state_path`), oldest first, and
        advance the watermark past everything returned -- including
        alerts that failed normalization, so a permanently malformed
        alert can't stall all future polling. Every result is also
        appended to `analysis_log_path`. Safe to call repeatedly,
        e.g. from a scheduler.
        """

        watermark = self._load_watermark()

        raw_alerts = self.indexer.search_alerts(
            query=query,
            limit=limit,
            since=watermark,
            ascending=True,
        )

        results = self._investigate(raw_alerts, top_k=top_k)

        for entry in results:
            self._log_analysis(entry)

        if raw_alerts:
            last_timestamp = raw_alerts[-1].get("timestamp")

            if last_timestamp:
                self._save_watermark(last_timestamp)

        return results

    def _investigate(
        self,
        raw_alerts: list[dict[str, Any]],
        top_k: int,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for raw_alert in raw_alerts:
            try:
                alert = normalize_wazuh_alert(raw_alert)

            except Exception as exc:
                results.append(
                    {
                        "alert": None,
                        "normalization_error": str(exc),
                        "raw_alert": raw_alert,
                        "analysis": None,
                    }
                )
                continue

            enrichment = self._enrich(alert)

            formatted_text = format_alert_for_ai(alert) + self._format_enrichment(
                enrichment
            )

            analysis = self.rag_pipeline.analyze(
                query=formatted_text,
                top_k=top_k,
            )

            threat_assessment = (
                parse_threat_assessment(analysis["response"])
                if analysis.get("guard_decision") == "ALLOW"
                else None
            )

            response_plan = build_response_plan(alert, threat_assessment)

            results.append(
                {
                    "alert": alert,
                    "normalization_error": None,
                    "raw_alert": raw_alert,
                    "enrichment": enrichment,
                    "analysis": analysis,
                    "threat_assessment": threat_assessment,
                    "response_plan": response_plan,
                }
            )

        return results

    def _enrich(self, alert: SecurityAlert) -> list[dict[str, Any]]:
        """
        Deterministically trigger read-only lookups through
        ToolExecutor based on fixed alert fields -- never based on
        anything the LLM decided. No-op if no tool_executor was
        given.
        """

        if self.tool_executor is None:
            return []

        enrichment: list[dict[str, Any]] = []

        if alert.source_ip:
            result = self.tool_executor.run(
                user_instruction=(
                    f"Look up threat intelligence for source IP "
                    f"{alert.source_ip} associated with alert "
                    f"{alert.rule_id}."
                ),
                tool_name="ThreatIntelLookupIP",
                tool_parameters={"ip_address": alert.source_ip},
            )
            enrichment.append({"tool": "ThreatIntelLookupIP", "result": result})

        if (
            alert.severity >= HIGH_SEVERITY_THRESHOLD
            and alert.agent_id
            and alert.agent_id != "unknown"
        ):
            result = self.tool_executor.run(
                user_instruction=(
                    f"Get the current status of agent {alert.agent_id} "
                    f"related to alert {alert.rule_id}."
                ),
                tool_name="WazuhGetAgentInfo",
                tool_parameters={"agent_id": alert.agent_id},
            )
            enrichment.append({"tool": "WazuhGetAgentInfo", "result": result})

        return enrichment

    @staticmethod
    def _format_enrichment(enrichment: list[dict[str, Any]]) -> str:
        if not enrichment:
            return ""

        lines = ["Automated enrichment:"]

        for item in enrichment:
            tool = item["tool"]
            result = item["result"]

            if result.status == "EXECUTED":
                lines.append(f"- {tool}: {result.output}")
            else:
                lines.append(f"- {tool}: {result.status}")

        return "\n\n" + "\n".join(lines)

    def _load_watermark(self) -> str | None:
        if not self.state_path.exists():
            return None

        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return data.get("last_processed_timestamp")

        except (json.JSONDecodeError, OSError):
            return None

    def _save_watermark(self, timestamp: str) -> None:
        self.state_path.write_text(
            json.dumps({"last_processed_timestamp": timestamp}),
            encoding="utf-8",
        )

    def _log_analysis(self, entry: dict[str, Any]) -> None:
        alert = entry["alert"]
        analysis = entry["analysis"]
        enrichment = entry.get("enrichment", [])
        threat_assessment: ThreatAssessment | None = entry.get(
            "threat_assessment"
        )
        response_plan: list[ProposedAction] = entry.get("response_plan", [])

        record = {
            "timestamp": entry["raw_alert"].get("timestamp"),
            "rule_id": alert.rule_id if alert else None,
            "rule_description": alert.rule_description if alert else None,
            "severity": alert.severity if alert else None,
            "normalization_error": entry["normalization_error"],
            "enrichment_tools": [item["tool"] for item in enrichment],
            "guard_decision": analysis["guard_decision"] if analysis else None,
            "guard_layer": analysis.get("guard_layer") if analysis else None,
            "threat_type": (
                threat_assessment.threat_type if threat_assessment else None
            ),
            "risk_level": (
                threat_assessment.risk_level if threat_assessment else None
            ),
            "confidence": (
                threat_assessment.confidence if threat_assessment else None
            ),
            "recommended_actions": (
                threat_assessment.recommended_actions
                if threat_assessment
                else None
            ),
            "proposed_actions": [
                {
                    "tool_name": action.tool_name,
                    "tool_parameters": action.tool_parameters,
                    "reason": action.reason,
                }
                for action in response_plan
            ],
            "response_summary": (
                analysis["response"][:500]
                if analysis and analysis.get("response")
                else None
            ),
        }

        with self.analysis_log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")
