"""
Ingest rag/knowledge/documents/*.md into the persistent
security_knowledge Qdrant collection (qdrant_storage) that the live
API/dashboard reads from.

Run from the project root:
    PYTHONPATH=. python rag/ingestion/build_knowledge_base.py

Must not run while anything else (e.g. the API server) holds
qdrant_storage open -- Qdrant's local/embedded mode allows only one
client at a time.

Safe to re-run after editing an existing document (upsert overwrites
points by id, which is assigned by position in the combined chunk
list). Adding or removing documents changes how many chunks precede
each other document's chunks, which can shift ids and leave stale
points behind -- not handled here, since this is a small, manually
curated starter corpus rather than a pipeline that runs unattended.
"""

from __future__ import annotations

from pathlib import Path

from rag.embeddings.embedder import EmbeddingModel
from rag.ingestion.chunker import chunk_documents
from rag.ingestion.loader import load_documents
from rag.retrieval.vector_store import LocalVectorStore

KNOWLEDGE_DIR = Path("rag/knowledge/documents")


def main() -> None:
    documents = load_documents(KNOWLEDGE_DIR)
    print(f"Loaded {len(documents)} documents from {KNOWLEDGE_DIR}")

    for document in documents:
        print(f"  - {document.source}")

    chunks = chunk_documents(documents)
    print(f"Split into {len(chunks)} chunks")

    embedder = EmbeddingModel()
    embeddings = embedder.encode_chunks(chunks)

    store = LocalVectorStore(collection_name="security_knowledge")
    store.upsert(chunks, embeddings)

    print(f"Upserted {len(chunks)} chunks into 'security_knowledge'")


if __name__ == "__main__":
    main()
