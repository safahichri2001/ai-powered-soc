from pathlib import Path

from rag.embeddings.embedder import EmbeddingModel
from rag.ingestion.chunker import chunk_documents
from rag.ingestion.loader import load_documents
from rag.retrieval.retriever import Retriever
from rag.retrieval.vector_store import LocalVectorStore


def test_retriever(tmp_path: Path) -> None:
    documents = load_documents(Path("rag/knowledge/documents"))
    chunks = chunk_documents(documents, max_chars=300)

    embedder = EmbeddingModel(device="cpu")
    embeddings = embedder.encode_chunks(chunks)

    store = LocalVectorStore(
        path=tmp_path / "qdrant",
        collection_name="test_security_knowledge",
    )

    store.upsert(chunks, embeddings)

    retriever = Retriever(
        vector_store=store,
    )

    results = retriever.search(
        "SSH authentication security",
        top_k=2,
    )

    assert retriever.count() == len(chunks)
    assert results
    assert len(results) <= 2
    assert results[0]["content"]
    assert results[0]["source"]