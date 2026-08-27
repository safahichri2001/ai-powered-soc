import json
from pathlib import Path


DATA_DIR = Path(
    "data/security/rag_poisoning/bipia"
)


def load_jsonl(path: Path) -> list[dict]:
    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return records


def test_bipia_has_100_pairs() -> None:
    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    assert len(clean) == 100
    assert len(poisoned) == 100


def test_bipia_pair_ids_match() -> None:
    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    clean_pairs = {
        record["pair_id"]
        for record in clean
    }

    poisoned_pairs = {
        record["pair_id"]
        for record in poisoned
    }

    assert clean_pairs == poisoned_pairs
    assert len(clean_pairs) == 100


def test_bipia_pairs_keep_same_task() -> None:
    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    clean_by_pair = {
        record["pair_id"]: record
        for record in clean
    }

    poisoned_by_pair = {
        record["pair_id"]: record
        for record in poisoned
    }

    for pair_id in clean_by_pair:
        clean_record = clean_by_pair[pair_id]
        poisoned_record = poisoned_by_pair[pair_id]

        assert (
            clean_record["task"]
            == poisoned_record["task"]
        )

        assert (
            clean_record["ideal"]
            == poisoned_record["ideal"]
        )

        assert (
            clean_record["context"]
            != poisoned_record["context"]
        )

        assert (
            poisoned_record["label"]
            == "poisoned"
        )

        assert poisoned_record[
            "attack_text"
        ]