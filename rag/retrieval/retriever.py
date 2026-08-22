from typing import Any

from rag.embeddings.embedder import EmbeddingModel
from rag.retrieval.vector_store import LocalVectorStore


class Retriever:
    """Retrieve relevant security knowledge from the vector store."""

    def __init__(
        self,
        vector_store: LocalVectorStore | None = None,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        self.vector_store = vector_store or LocalVectorStore()
        self.embedder = EmbeddingModel(model_name=model_name)

    def search(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Retrieve the most relevant knowledge chunks."""

        if not query.strip():
            return []

        query_embedding = (
            self.embedder.model.encode(
                query,
                normalize_embeddings=True,
                convert_to_numpy=True,
            )
            .tolist()
        )

        results = self.vector_store.client.query_points(
            collection_name=self.vector_store.collection_name,
            query=query_embedding,
            limit=top_k,
        )

        return [
            {
                "score": point.score,
                "chunk_id": point.payload.get("chunk_id"),
                "source": point.payload.get("source"),
                "content": point.payload.get("content"),
            }
            for point in results.points
        ]

    def count(self) -> int:
        """Return the number of indexed chunks."""

        return self.vector_store.count()