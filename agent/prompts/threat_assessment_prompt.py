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
