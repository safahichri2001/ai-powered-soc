from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from rag.ingestion.chunker import DocumentChunk


class LocalVectorStore:
    """Local Qdrant vector store for the security knowledge base."""

    def __init__(
        self,
        path: str | Path = "qdrant_storage",
        collection_name: str = "security_knowledge",
        vector_size: int = 384,
    ) -> None:
        self.collection_name = collection_name
        self.client = QdrantClient(path=str(path))

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