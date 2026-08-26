import json
from collections import Counter
from pathlib import Path


SECURITY_DIR = Path(__file__).parent

INPUT_FILE = SECURITY_DIR / "all_datasets_merged.jsonl"
OUTPUT_FILE = SECURITY_DIR / "prompt_injection_corpus.jsonl"


PROMPT_INJECTION_CATEGORIES = {
    "instruction_override",
    "role_hijacking",
    "system_prompt_extraction",
    "policy_bypass",
    "context_manipulation",
    "indirect_injection",
    "delimiter_injection",
    "encoding_bypass",
    "jailbreak",
    "obfuscation",
    "multi_step",
}

VALID_LABELS = {"attack", "benign"}


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL records."""

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    records: list[dict] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path}:{line_number}"
                ) from exc

    return records


def normalize_text(text: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(
        str(text).strip().lower().split()
    )


def main() -> None:
    """Build the prompt-injection-specific corpus."""

    records = load_jsonl(INPUT_FILE)

    selected: list[dict] = []
    seen: set[str] = set()
    skipped_attack_categories: Counter[str] = Counter()
    duplicates_removed = 0

    for record in records:
        label = str(record["label"]).strip().lower()
        category = str(record["category"]).strip().lower()

        if label not in VALID_LABELS:
            raise ValueError(
                f"Invalid label: {label}"
            )

        # Keep every benign example.
        # Keep only attack categories relevant to prompt injection.
        if label == "attack":
            if category not in PROMPT_INJECTION_CATEGORIES:
                skipped_attack_categories[category] += 1
                continue

        normalized = normalize_text(record["text"])

        if normalized in seen:
            duplicates_removed += 1
            continue

        seen.add(normalized)

        selected.append(record)

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in selected:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    labels = Counter(
        record["label"]
        for record in selected
    )

    categories = Counter(
        record["category"]
        for record in selected
    )

    sources = Counter(
        record["source"]
        for record in selected
    )

    print("=== PROMPT INJECTION CORPUS ===")
    print(f"Input records:              {len(records)}")
    print(f"Selected records:           {len(selected)}")
    print(f"Duplicates removed:         {duplicates_removed}")

    print("\n=== LABELS ===")
    for label, count in sorted(labels.items()):
        print(f"{label:<15} {count}")

    print("\n=== CATEGORIES ===")
    for category, count in sorted(categories.items()):
        print(f"{category:<30} {count}")

    print("\n=== SOURCES ===")
    for source, count in sorted(sources.items()):
        print(f"{source:<30} {count}")

    print("\n=== EXCLUDED ATTACK CATEGORIES ===")
    for category, count in sorted(
        skipped_attack_categories.items()
    ):
        print(f"{category:<30} {count}")

    print("\n=== OUTPUT ===")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()