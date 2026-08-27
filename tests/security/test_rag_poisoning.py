import json
from pathlib import Path


DATA_DIR = Path(
    "data/security/rag_poisoning"
)


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL records."""

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    records: list[dict] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at "
                    f"{path}:{line_number}"
                ) from exc

    return records


def test_clean_documents_are_valid() -> None:
    """Validate clean RAG documents."""

    records = load_jsonl(
        DATA_DIR / "clean_documents.jsonl"
    )

    assert len(records) == 20

    for record in records:
        assert record["id"]
        assert record["text"]
        assert record["category"]
        assert record["label"] == "clean"


def test_poisoned_documents_are_valid() -> None:
    """Validate poisoned RAG documents."""

    records = load_jsonl(
        DATA_DIR / "poisoned_documents.jsonl"
    )

    assert len(records) == 20

    for record in records:
        assert record["id"]
        assert record["text"]
        assert record["category"]
        assert record["label"] == "poisoned"


def test_clean_and_poisoned_corpus_are_balanced() -> None:
    """Ensure the smoke-test corpus is balanced."""

    clean = load_jsonl(
        DATA_DIR / "clean_documents.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned_documents.jsonl"
    )

    assert len(clean) == 20
    assert len(poisoned) == 20
    assert len(clean) == len(poisoned)