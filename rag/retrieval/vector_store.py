import os
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from rag.ingestion.chunker import DocumentChunk


class LocalVectorStore:
    """
    Qdrant vector store for the security knowledge base.

    Embedded/local-file mode (the default, `path=`) is what this
    project has always run with outside Docker -- only one
    process can open that file store at a time. Pass `url=` instead
    to connect to a real Qdrant server (e.g. the `qdrant` service in
    docker-compose.yml), which supports concurrent access.
    """

    def __init__(
        self,
        path: str | Path = "qdrant_storage",
        collection_name: str = "security_knowledge",
        vector_size: int = 384,
        url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.collection_name = collection_name
        self.client = (
            QdrantClient(url=url, api_key=api_key)
            if url
            else QdrantClient(path=str(path))
        )

        collections = {
            collection.name
            for collection in self.client.get_collections().collections
        }

        if collection_name not in collections:
            self.client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(
                    size=vector_size,
                    distance=Distance.COSINE,
                ),
            )

    def upsert(
        self,
        chunks: list[DocumentChunk],
        embeddings: list[list[float]],
    ) -> None:
        """Store document chunks and their embeddings."""

        if len(chunks) != len(embeddings):
            raise ValueError(
                "Chunks and embeddings must have the same length."
            )

        points = [
            PointStruct(
                id=index,
                vector=embedding,
                payload={
                    "chunk_id": chunk.chunk_id,
                    "source": chunk.source,
                    "content": chunk.content,
                },
            )
            for index, (chunk, embedding) in enumerate(
                zip(chunks, embeddings)
            )
        ]

        if points:
            self.client.upsert(
                collection_name=self.collection_name,
                points=points,
            )

    def count(self) -> int:
        """Return the number of stored vectors."""

        collection = self.client.get_collection(self.collection_name)
        return collection.points_count or 0


def build_vector_store(
    collection_name: str = "security_knowledge",
) -> LocalVectorStore:
    """
    Build the vector store for the current environment.

    Gated on RUNNING_IN_DOCKER rather than the mere presence of
    QDRANT_URL: a developer's local .env already declares
    QDRANT_URL (for when the container needs it) even when running
    outside Docker, where nothing is listening on it -- so presence
    alone can't be the signal. RUNNING_IN_DOCKER is set only by
    docker-compose.yml, never by a local .env, so local runs keep
    using the embedded file store exactly as before.
    """

    if os.environ.get("RUNNING_IN_DOCKER") == "1":
        return LocalVectorStore(
            collection_name=collection_name,
            url=os.environ.get("QDRANT_URL", "http://qdrant:6333"),
            api_key=os.environ.get("QDRANT_API_KEY") or None,
        )

    return LocalVectorStore(collection_name=collection_name)