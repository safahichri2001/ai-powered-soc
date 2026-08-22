from sentence_transformers import SentenceTransformer

from rag.ingestion.chunker import DocumentChunk


class EmbeddingModel:
    """Generate vector embeddings for security knowledge chunks."""

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        device: str | None = None,
    ) -> None:
        self.model = SentenceTransformer(
            model_name,
            device=device,
        )

    def encode_chunks(
        self,
        chunks: list[DocumentChunk],
    ) -> list[list[float]]:
        """Generate one embedding vector per document chunk."""

        if not chunks:
            return []

        texts = [chunk.content for chunk in chunks]

        embeddings = self.model.encode(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

        return embeddings.tolist()