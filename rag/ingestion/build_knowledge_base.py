"""
Ingest rag/knowledge/documents/*.md into the persistent
security_knowledge Qdrant collection that the live API/dashboard
reads from -- the local embedded store (qdrant_storage) outside
Docker, or the qdrant service when RUNNING_IN_DOCKER=1 (see
rag/retrieval/vector_store.py's build_vector_store()).

Run from the project root:
    PYTHONPATH=. python rag/ingestion/build_knowledge_base.py

Outside Docker, must not run while anything else (e.g. the API
server) holds qdrant_storage open -- the embedded local-file mode
allows only one client at a time. Inside Docker, run it as a
one-off command against the running stack instead, e.g.:
    docker compose run --rm api python rag/ingestion/build_knowledge_base.py

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
from rag.retrieval.vector_store import build_vector_store

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

    store = build_vector_store()
    store.upsert(chunks, embeddings)

    print(f"Upserted {len(chunks)} chunks into 'security_knowledge'")


if __name__ == "__main__":
    main()
