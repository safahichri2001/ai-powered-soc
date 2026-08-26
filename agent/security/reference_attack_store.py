import json
from pathlib import Path

from sentence_transformers import SentenceTransformer


class ReferenceAttackStore:
    """Load and encode reference prompt-injection examples once."""

    def __init__(
        self,
        dataset_path: str | Path,
        model: SentenceTransformer,
    ) -> None:
        self.dataset_path = Path(dataset_path)
        self.model = model

        self.texts: list[str] = []
        self.embeddings = None

        self._load()
        self._encode()

    def _load(self) -> None:
        """Load attack examples from the reference JSONL file."""

        if not self.dataset_path.exists():
            raise FileNotFoundError(
                f"Reference dataset not found: {self.dataset_path}"
            )

        records: list[dict] = []

        with self.dataset_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON at "
                        f"{self.dataset_path}:{line_number}"
                    ) from exc

                records.append(record)

        self.texts = [
            str(record["text"])
            for record in records
            if record.get("label") == "attack"
        ]

        if not self.texts:
            raise ValueError(
                "Reference dataset contains no attack examples."
            )

    def _encode(self) -> None:
        """Encode reference attack examples once."""

        self.embeddings = self.model.encode(
            self.texts,
            normalize_embeddings=True,
            convert_to_tensor=True,
            show_progress_bar=True,
        )

    @property
    def size(self) -> int:
        """Return the number of reference attacks."""

        return len(self.texts)