from pathlib import Path

from rag.ingestion.chunker import chunk_documents
from rag.ingestion.loader import load_documents


def test_chunk_documents() -> None:
    documents = load_documents(Path("rag/knowledge/documents"))

    chunks = chunk_documents(documents, max_chars=300)

    assert chunks
    assert all(chunk.content.strip() for chunk in chunks)
    assert all(chunk.source for chunk in chunks)