from pathlib import Path

from rag.embeddings.embedder import EmbeddingModel
from rag.ingestion.chunker import chunk_documents
from rag.ingestion.loader import load_documents


def test_encode_chunks() -> None:
    documents = load_documents(Path("rag/knowledge/documents"))
    chunks = chunk_documents(documents, max_chars=300)

    embedder = EmbeddingModel(device="cpu")
    embeddings = embedder.encode_chunks(chunks)

    assert len(embeddings) == len(chunks)
    assert embeddings
    assert all(isinstance(vector, list) for vector in embeddings)
    assert all(len(vector) > 0 for vector in embeddings)