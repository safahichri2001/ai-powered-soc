from dataclasses import dataclass
from pathlib import Path


@dataclass
class KnowledgeDocument:
    """A document loaded from the security knowledge base."""

    source: str
    content: str


def load_documents(directory: str | Path) -> list[KnowledgeDocument]:
    """Load Markdown documents from a directory."""

    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(f"Knowledge base directory not found: {directory}")

    documents: list[KnowledgeDocument] = []

    for file_path in sorted(directory.glob("*.md")):
        content = file_path.read_text(encoding="utf-8").strip()

        if not content:
            continue

        documents.append(
            KnowledgeDocument(
                source=file_path.name,
                content=content,
            )
        )

    return documents