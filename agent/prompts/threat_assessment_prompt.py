from textwrap import dedent


def build_threat_assessment_prompt(
    query: str,
    context: str,
) -> str:
    """
    Build a prompt asking the LLM for a structured, machine-readable
    threat assessment instead of free-form prose. This is what lets a
    downstream decision/playbook step branch on `risk_level` rather
    than parsing English sentences -- the "decision engine" piece of
    a SIEM -> AI -> SOAR pipeline.

    Used for the alert-investigation path (LiveAlertInvestigator)
    specifically, not the general chat path (RAGPipeline used
    directly) -- a human asking a free-form question should get a
    readable answer back, not forced JSON.
    """

    return dedent(
        f"""
        You are a cybersecurity analyst assisting a Security Operations Center.

        Analyze the alert below using ONLY the provided security context
        for factual claims. Do not invent facts not supported by the context.

        Use these concrete criteria for risk_level -- do not default to LOW
        or MEDIUM out of caution when the evidence supports higher, but also
        never raise risk_level above what the alert's own content actually
        supports:
        - CRITICAL: the rule description and data themselves describe
          confirmed compromise, active exploitation, data exfiltration, or
          a correlation/aggregate rule (repeated failures, multiple
          attempts) AND Wazuh severity is 10 or above.
        - HIGH: the rule description itself indicates malicious or attack
          activity (not just a routine system change), and/or Wazuh
          severity is 7-9.
        - MEDIUM: suspicious but ambiguous activity, or an isolated system
          event with unclear intent, Wazuh severity 4-6.
        - LOW: routine, expected activity (successful login, normal
          service start/stop, a configuration change with no attack
          indicator), Wazuh severity 0-3.

        Base threat_type strictly on what THIS alert's own rule description
        and data actually say. Never reuse a category name from the
        criteria above unless this alert's own content genuinely matches
        it -- a change in listened ports, a login, or a routine system
        message is NOT a brute force attempt, malware, or exploitation
        unless the alert itself describes one.

        The alert's "Severity" field below is one signal among several,
        not an automatic override -- weigh it together with what the rule
        description and data actually describe.

        Security context:
        ---
        {context}
        ---

        Alert:
        ---
        {query}
        ---

        Respond with EXACTLY one block in this format, and nothing else
        outside it:

        <THREAT_ASSESSMENT>
        {{
          "threat_type": "<short attack/event category>",
          "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
          "confidence": <number between 0.0 and 1.0>,
          "summary": "<one to two sentence explanation grounded in the context above>",
          "recommended_actions": ["<action 1>", "<action 2>"]
        }}
        </THREAT_ASSESSMENT>

        If the context is insufficient to assess confidently, still return
        the block, using "INSUFFICIENT_CONTEXT" as threat_type, "LOW" as
        risk_level, and explain what's missing in summary.
        """
    ).strip()
