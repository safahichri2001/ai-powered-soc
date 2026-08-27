import json
from pathlib import Path

from sentence_transformers import SentenceTransformer


class BIPIAAttackStore:
    """Store semantic representations of BIPIA attack strings."""

    def __init__(
        self,
        attack_file: str | Path,
        model: SentenceTransformer,
    ) -> None:
        self.attack_file = Path(attack_file)
        self.model = model

        self.attacks: list[str] = []
        self.embeddings = None

        self._load()
        self._encode()

    def _load(self) -> None:
        """Load BIPIA attack strings."""

        if not self.attack_file.exists():
            raise FileNotFoundError(
                f"Attack file not found: {self.attack_file}"
            )

        with self.attack_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        for family, attack_list in data.items():
            for attack in attack_list:
                self.attacks.append(
                    str(attack).strip()
                )

        if not self.attacks:
            raise ValueError(
                "No BIPIA attacks found."
            )

    def _encode(self) -> None:
        """Encode attack strings once."""

        self.embeddings = self.model.encode(
            self.attacks,
            normalize_embeddings=True,
            convert_to_tensor=True,
            show_progress_bar=True,
        )

    @property
    def size(self) -> int:
        return len(self.attacks)