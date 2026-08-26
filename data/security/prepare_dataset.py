import json
import random
from collections import Counter, defaultdict
from pathlib import Path


SECURITY_DIR = Path(__file__).parent

INPUT_FILE = SECURITY_DIR / "prompt_injection_corpus.jsonl"
OUTPUT_DIR = SECURITY_DIR / "prepared"

RANDOM_SEED = 42

REFERENCE_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

assert abs(
    REFERENCE_RATIO + VALIDATION_RATIO + TEST_RATIO - 1.0
) < 1e-9


def load_jsonl(path: Path) -> list[dict]:
    """Load records from a JSONL file."""

    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

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


def validate_records(records: list[dict]) -> None:
    """Validate the common dataset schema."""

    required_fields = {
        "id",
        "text",
        "category",
        "label",
        "source",
        "source_id",
    }

    valid_labels = {"attack", "benign"}

    for record in records:
        missing = required_fields - record.keys()

        if missing:
            raise ValueError(
                f"Record {record.get('id')} is missing: {sorted(missing)}"
            )

        if not str(record["text"]).strip():
            raise ValueError(
                f"Record {record['id']} contains empty text."
            )

        if record["label"] not in valid_labels:
            raise ValueError(
                f"Invalid label in record {record['id']}: "
                f"{record['label']}"
            )


def deduplicate_records(records: list[dict]) -> list[dict]:
    """Remove duplicate prompts after normalization."""

    seen: set[str] = set()
    unique_records: list[dict] = []

    for record in records:
        normalized = " ".join(
            str(record["text"])
            .strip()
            .lower()
            .split()
        )

        if normalized in seen:
            continue

        seen.add(normalized)
        unique_records.append(record)

    return unique_records


def stratified_split(
    records: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Split records while preserving the attack/benign ratio.

    Categories are kept for analysis, but are not used as mandatory
    strata because some categories are too small to support a 60/20/20 split.
    """

    strata: dict[str, list[dict]] = defaultdict(list)

    for record in records:
        strata[str(record["label"])].append(record)

    reference: list[dict] = []
    validation: list[dict] = []
    test: list[dict] = []

    for label, group in sorted(strata.items()):
        random.shuffle(group)

        total = len(group)

        reference_count = round(total * REFERENCE_RATIO)
        validation_count = round(total * VALIDATION_RATIO)

        # Guarantee at least one test example.
        if reference_count + validation_count >= total:
            test_count = 1
            validation_count = max(1, validation_count - 1)
            reference_count = total - validation_count - test_count
        else:
            test_count = total - reference_count - validation_count

        reference.extend(group[:reference_count])

        validation.extend(
            group[
                reference_count:
                reference_count + validation_count
            ]
        )

        test.extend(
            group[
                reference_count + validation_count:
                reference_count + validation_count + test_count
            ]
        )

    random.shuffle(reference)
    random.shuffle(validation)
    random.shuffle(test)

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
    """Print label and category distributions."""

    labels = Counter(
        record["label"]
        for record in records
    )

    categories = Counter(
        (
            record["label"],
            record["category"],
        )
        for record in records
    )

    print(f"\n=== {name.upper()} ===")
    print(f"Total: {len(records)}")

    print("\nLabels:")
    for label, count in sorted(labels.items()):
        print(f"  {label}: {count}")

    print("\nLabel + category:")
    for (label, category), count in sorted(categories.items()):
        print(
            f"  {label:>6} | "
            f"{category:<30} | {count}"
        )


def main() -> None:
    """Prepare the final reference, validation, and test datasets."""

    random.seed(RANDOM_SEED)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = load_jsonl(INPUT_FILE)

    print("=== INPUT DATASET ===")
    print(f"Records loaded: {len(records)}")

    validate_records(records)

    before = len(records)

    records = deduplicate_records(records)

    after = len(records)

    print(f"Duplicates removed: {before - after}")
    print(f"Records after deduplication: {after}")

    reference, validation, test = stratified_split(records)

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

    print_distribution("reference", reference)
    print_distribution("validation", validation)
    print_distribution("test", test)

    print("\n=== OUTPUT FILES ===")
    print(
        f"Reference : "
        f"{OUTPUT_DIR / 'reference.jsonl'}"
    )
    print(
        f"Validation: "
        f"{OUTPUT_DIR / 'validation.jsonl'}"
    )
    print(
        f"Test      : "
        f"{OUTPUT_DIR / 'test.jsonl'}"
    )


if __name__ == "__main__":
    main()