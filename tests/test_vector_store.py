from pathlib import Path

from rag.embeddings.embedder import EmbeddingModel
from rag.ingestion.chunker import chunk_documents
from rag.ingestion.loader import load_documents
from rag.retrieval.vector_store import LocalVectorStore


def test_vector_store(tmp_path) -> None:
    documents = load_documents(Path("rag/knowledge/documents"))
    chunks = chunk_documents(documents, max_chars=300)

    embedder = EmbeddingModel(device="cpu")
    embeddings = embedder.encode_chunks(chunks)

    store = LocalVectorStore(
        collection_name="test_security_knowledge",
    )

    store.upsert(chunks, embeddings)

    collection = store.client.get_collection(
        "test_security_knowledge"
    )

    assert collection.points_count == len(chunks)