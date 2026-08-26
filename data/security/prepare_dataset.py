import json
import random
from pathlib import Path
from collections import Counter


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "prepared"

ATTACK_FILE = DATA_DIR / "prompt_injection.jsonl"
BENIGN_FILE = DATA_DIR / "benign_prompts.jsonl"

RANDOM_SEED = 42

# 60% reference, 20% validation, 20% test
REFERENCE_RATIO = 0.60
VALIDATION_RATIO = 0.20
TEST_RATIO = 0.20


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL records from a file."""

    records: list[dict] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_number}"
                ) from exc

            records.append(record)

    return records


def validate_records(
    records: list[dict],
    expected_label: str,
) -> None:
    """Validate required fields and expected labels."""

    required_fields = {"id", "text", "category", "label"}

    for record in records:
        missing = required_fields - record.keys()

        if missing:
            raise ValueError(
                f"Missing fields in record {record.get('id')}: {missing}"
            )

        if not str(record["text"]).strip():
            raise ValueError(
                f"Empty text in record {record['id']}"
            )

        if record["label"] != expected_label:
            raise ValueError(
                f"Unexpected label in record {record['id']}: "
                f"{record['label']}"
            )


def remove_duplicates(records: list[dict]) -> list[dict]:
    """Remove duplicate examples based on normalized text."""

    seen: set[str] = set()
    unique_records: list[dict] = []

    for record in records:
        normalized_text = " ".join(
            str(record["text"]).lower().split()
        )

        if normalized_text in seen:
            continue

        seen.add(normalized_text)
        unique_records.append(record)

    return unique_records


def split_records(
    records: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split records into reference, validation, and test sets."""

    shuffled = records.copy()
    random.shuffle(shuffled)

    total = len(shuffled)

    reference_end = int(total * REFERENCE_RATIO)
    validation_end = reference_end + int(total * VALIDATION_RATIO)

    reference = shuffled[:reference_end]
    validation = shuffled[reference_end:validation_end]
    test = shuffled[validation_end:]

    return reference, validation, test


def write_jsonl(
    records: list[dict],
    path: Path,
) -> None:
    """Write records to a JSONL file."""

    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )


def print_distribution(
    name: str,
    records: list[dict],
) -> None:
    """Print category distribution."""

    categories = Counter(
        record["category"]
        for record in records
    )

    print(f"\n{name}: {len(records)} examples")

    for category, count in sorted(categories.items()):
        print(f"  {category}: {count}")


def main() -> None:
    random.seed(RANDOM_SEED)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    attacks = load_jsonl(ATTACK_FILE)
    benign = load_jsonl(BENIGN_FILE)

    validate_records(attacks, "attack")
    validate_records(benign, "benign")

    attacks = remove_duplicates(attacks)
    benign = remove_duplicates(benign)

    print("=== DATASET AFTER VALIDATION ===")
    print(f"Attack examples: {len(attacks)}")
    print(f"Benign examples: {len(benign)}")

    attack_reference, attack_validation, attack_test = split_records(
        attacks
    )

    benign_reference, benign_validation, benign_test = split_records(
        benign
    )

    reference = attack_reference + benign_reference
    validation = attack_validation + benign_validation
    test = attack_test + benign_test

    random.shuffle(reference)
    random.shuffle(validation)
    random.shuffle(test)

    write_jsonl(
        reference,
        OUTPUT_DIR / "reference.jsonl",
    )

    write_jsonl(
        validation,
        OUTPUT_DIR / "validation.jsonl",
    )

    write_jsonl(
        test,
        OUTPUT_DIR / "test.jsonl",
    )

    print_distribution("REFERENCE", reference)
    print_distribution("VALIDATION", validation)
    print_distribution("TEST", test)

    print("\n=== OUTPUT ===")
    print(f"Reference : {OUTPUT_DIR / 'reference.jsonl'}")
    print(f"Validation: {OUTPUT_DIR / 'validation.jsonl'}")
    print(f"Test      : {OUTPUT_DIR / 'test.jsonl'}")


if __name__ == "__main__":
    main()