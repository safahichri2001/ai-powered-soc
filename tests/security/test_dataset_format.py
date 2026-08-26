import json
from pathlib import Path


DATA_DIR = Path("data/security")


def load_jsonl(path: Path) -> list[dict]:
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"Invalid JSON on line {line_number} of {path}"
                ) from exc

            records.append(record)

    return records


def test_prompt_injection_dataset() -> None:
    path = DATA_DIR / "prompt_injection.jsonl"
    records = load_jsonl(path)

    assert records

    for record in records:
        assert record["id"]
        assert record["text"]
        assert record["category"]
        assert record["label"] == "attack"


def test_benign_dataset() -> None:
    path = DATA_DIR / "benign_prompts.jsonl"
    records = load_jsonl(path)

    assert records

    for record in records:
        assert record["id"]
        assert record["text"]
        assert record["category"]
        assert record["label"] == "benign"