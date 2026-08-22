from dataclasses import dataclass

from rag.ingestion.loader import KnowledgeDocument


@dataclass
class DocumentChunk:
    """A chunk extracted from a knowledge document."""

    chunk_id: str
    source: str
    content: str


def chunk_documents(
    documents: list[KnowledgeDocument],
    max_chars: int = 800,
) -> list[DocumentChunk]:
    """Split documents into simple overlapping-free chunks."""

    chunks: list[DocumentChunk] = []

    for document in documents:
        paragraphs = [
            paragraph.strip()
            for paragraph in document.content.split("\n\n")
            if paragraph.strip()
        ]

        current: list[str] = []
        current_size = 0
        chunk_index = 0

        for paragraph in paragraphs:
            paragraph_size = len(paragraph)

            if current and current_size + paragraph_size + 2 > max_chars:
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"{document.source}:{chunk_index}",
                        source=document.source,
                        content="\n\n".join(current),
                    )
                )

                chunk_index += 1
                current = []
                current_size = 0

            current.append(paragraph)
            current_size += paragraph_size + 2

        if current:
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{document.source}:{chunk_index}",
                    source=document.source,
                    content="\n\n".join(current),
                )
            )

    return chunks