import json
import statistics
from collections import Counter
from pathlib import Path


DATASET_PATH = Path(
    "data/external/kaggle_prompt_injection/raw/"
    "Prompt_INJECTION_And_Benign_DATASET.jsonl"
)


REQUIRED_FIELDS = {
    "id",
    "prompt",
    "label",
    "attack_type",
    "context",
    "response",
}


def normalize_text(text: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(
        str(text).strip().lower().split()
    )


def main() -> None:
    records: list[dict] = []

    with DATASET_PATH.open(
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
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from exc

            records.append(record)

    print("\n=== KAGGLE DATASET AUDIT ===\n")
    print(f"File: {DATASET_PATH}")
    print(f"Rows: {len(records)}")

    if not records:
        raise ValueError("Dataset is empty.")

    # Columns / fields
    fields = set(records[0].keys())

    print("\n=== FIELDS ===")
    for field in sorted(fields):
        print(f"- {field}")

    missing_fields = REQUIRED_FIELDS - fields

    if missing_fields:
        print(
            "\nWARNING - Missing fields:",
            sorted(missing_fields),
        )

    # Labels
    labels = Counter(
        record.get("label")
        for record in records
    )

    print("\n=== LABELS ===")
    for label, count in labels.most_common():
        print(f"{label}: {count}")

    # Attack types
    attack_types = Counter(
        record.get("attack_type")
        for record in records
    )

    print("\n=== ATTACK TYPES ===")
    for attack_type, count in attack_types.most_common():
        print(f"{attack_type}: {count}")

    # Missing values
    print("\n=== MISSING VALUES ===")

    for field in sorted(REQUIRED_FIELDS):
        missing = sum(
            record.get(field) is None
            or not str(record.get(field)).strip()
            for record in records
        )

        print(f"{field}: {missing}")

    # Empty prompts
    empty_prompts = sum(
        not str(record.get("prompt", "")).strip()
        for record in records
    )

    print("\n=== EMPTY PROMPTS ===")
    print(f"Empty prompts: {empty_prompts}")

    # Exact duplicates
    prompt_values = [
        str(record.get("prompt", ""))
        for record in records
    ]

    exact_duplicates = (
        len(prompt_values) - len(set(prompt_values))
    )

    print("\n=== DUPLICATES ===")
    print(
        f"Exact prompt duplicates: "
        f"{exact_duplicates}"
    )

    # Normalized duplicates
    normalized_prompts = [
        normalize_text(prompt)
        for prompt in prompt_values
    ]

    normalized_duplicates = (
        len(normalized_prompts)
        - len(set(normalized_prompts))
    )

    print(
        f"Normalized prompt duplicates: "
        f"{normalized_duplicates}"
    )

    # Prompt lengths
    prompt_lengths = [
        len(prompt)
        for prompt in prompt_values
    ]

    print("\n=== PROMPT LENGTH ===")
    print(f"Minimum: {min(prompt_lengths)}")
    print(f"Maximum: {max(prompt_lengths)}")
    print(
        f"Mean:    "
        f"{statistics.mean(prompt_lengths):.2f}"
    )
    print(
        f"Median:  "
        f"{statistics.median(prompt_lengths):.2f}"
    )

    # Label × attack type
    print("\n=== LABEL × ATTACK TYPE ===")

    combinations = Counter(
        (
            record.get("label"),
            record.get("attack_type"),
        )
        for record in records
    )

    for (label, attack_type), count in sorted(
        combinations.items()
    ):
        print(
            f"{label:<12} "
            f"{attack_type:<25} "
            f"{count}"
        )

    # Sample IDs
    print("\n=== ID CHECK ===")

    ids = [
        str(record.get("id"))
        for record in records
    ]

    duplicate_ids = (
        len(ids) - len(set(ids))
    )

    print(f"Duplicate IDs: {duplicate_ids}")

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()