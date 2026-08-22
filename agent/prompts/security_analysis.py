from textwrap import dedent


def build_security_analysis_prompt(
    query: str,
    context: str,
) -> str:
    """Build a grounded security-analysis prompt."""

    return dedent(
        f"""
        You are a cybersecurity analyst assisting a Security Operations Center.

        Your task is to analyze the user's security query using ONLY the
        provided security context when making factual claims.

        Do not invent facts that are not supported by the context.

        Security context:
        ---
        {context}
        ---

        User query:
        ---
        {query}
        ---

        Provide a concise analysis with:
        1. Event interpretation
        2. Risk assessment
        3. Evidence from the provided context
        4. Recommended investigation steps

        If the context is insufficient, explicitly say that more evidence
        is required.
        """
    ).strip()