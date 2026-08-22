from typing import Any


def build_context(results: list[dict[str, Any]]) -> str:
    """Build a structured context from retrieved knowledge."""

    if not results:
        return "No relevant security knowledge was retrieved."

    sections: list[str] = []

    for index, result in enumerate(results, start=1):
        source = result.get("source", "unknown")
        score = result.get("score")
        content = str(result.get("content", "")).strip()

        if not content:
            continue

        header = f"[Source {index}: {source}]"

        if score is not None:
            header += f" [Similarity: {float(score):.4f}]"

        sections.append(f"{header}\n{content}")

    if not sections:
        return "No relevant security knowledge was retrieved."

    return "\n\n".join(sections)