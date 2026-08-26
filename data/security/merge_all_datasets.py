import json
import unicodedata
from collections import Counter
from pathlib import Path


SECURITY_DIR = Path(__file__).parent

INPUT_FILES = [
    (
        SECURITY_DIR / "prompt_injection.jsonl",
        "curated",
    ),
    (
        SECURITY_DIR / "benign_prompts.jsonl",
        "curated",
    ),
    (
        SECURITY_DIR
        / "external"
        / "prompt_injection_benchmark.jsonl",
        "prompt_injection_benchmark",
    ),
    (
        SECURITY_DIR
        / "external"
        / "kaggle_prompt_injection.jsonl",
        "kaggle_prompt_injection",
    ),
]

OUTPUT_FILE = SECURITY_DIR / "all_datasets_merged.jsonl"

VALID_LABELS = {"attack", "benign"}

CATEGORY_MAPPING = {
    # Attack categories
    "instruction_override": "instruction_override",
    "role_hijack": "role_hijacking",
    "role_hijacking": "role_hijacking",
    "system_prompt_leak": "system_prompt_extraction",
    "system_prompt_extraction": "system_prompt_extraction",
    "policy_bypass": "policy_bypass",
    "context_manipulation": "context_manipulation",
    "indirect_injection": "indirect_injection",
    "obfuscation": "obfuscation",
    "delimiter_injection": "delimiter_injection",
    "encoding_bypass": "encoding_bypass",
    "jailbreak": "jailbreak",
    "data_exfiltration": "data_exfiltration",
    "multi_step": "multi_step",
    "tool_or_code_execution": "tool_or_code_execution",

    # Benign categories
    "benign": "benign",
    "ssh": "ssh",
    "sudo": "sudo",
    "wazuh": "wazuh",
    "rag": "rag",
    "linux": "linux",
    "authentication": "authentication",
    "incident_response": "incident_response",
    "mitre_attack": "mitre_attack",
}


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
                    f"Invalid JSON in {path} line {line_number}"
                ) from exc

    return records


def repair_text(text: str) -> str:
    """Repair common UTF-8/Latin-1 mojibake."""

    text = str(text).strip()

    if "Ã" in text or "Â" in text:
        try:
            text = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    return unicodedata.normalize("NFC", text)


def normalize_duplicate_text(text: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(
        repair_text(text).lower().split()
    )


def normalize_category(category: str) -> str:
    """Map source categories to the canonical taxonomy."""

    normalized = category.strip().lower()

    if normalized not in CATEGORY_MAPPING:
        raise ValueError(
            f"Unknown category: {category}"
        )

    return CATEGORY_MAPPING[normalized]


def normalize_record(
    record: dict,
    source_name: str,
    index: int,
) -> dict:
    """Normalize one source record."""

    required_fields = {
        "id",
        "text",
        "category",
        "label",
    }

    missing = required_fields - record.keys()

    if missing:
        raise ValueError(
            f"Record {record.get('id')} from {source_name} "
            f"is missing: {sorted(missing)}"
        )

    label = str(record["label"]).strip().lower()

    if label not in VALID_LABELS:
        raise ValueError(
            f"Invalid label '{label}' in "
            f"{source_name}:{record.get('id')}"
        )

    text = repair_text(record["text"])

    if not text:
        raise ValueError(
            f"Empty text in {source_name}:{record.get('id')}"
        )

    return {
        "id": f"{source_name}_{index:04d}",
        "text": text,
        "category": normalize_category(
            str(record["category"])
        ),
        "label": label,
        "severity": str(
            record.get("severity", "unknown")
        ).strip().lower(),
        "source": source_name,
        "source_id": str(
            record.get(
                "source_id",
                record["id"],
            )
        ),
    }


def main() -> None:
    """Merge, normalize, clean and deduplicate all datasets."""

    all_records: list[dict] = []

    print("=== INPUT SOURCES ===")

    for path, source_name in INPUT_FILES:
        records = load_jsonl(path)

        print(
            f"{source_name:<30} "
            f"{len(records):>4} records"
        )

        for index, record in enumerate(
            records,
            start=1,
        ):
            all_records.append(
                normalize_record(
                    record,
                    source_name,
                    index,
                )
            )

    before = len(all_records)

    seen: dict[str, dict] = {}
    duplicates_removed = 0

    for record in all_records:
        key = normalize_duplicate_text(
            record["text"]
        )

        if key in seen:
            duplicates_removed += 1

            existing = seen[key]

            print("\nDUPLICATE DETECTED")
            print(
                f"Existing source: "
                f"{existing['source']} "
                f"({existing['source_id']})"
            )
            print(
                f"Duplicate source: "
                f"{record['source']} "
                f"({record['source_id']})"
            )
            print(
                f"Text: {record['text']}"
            )

            continue

        seen[key] = record

    merged = list(seen.values())

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in merged:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    labels = Counter(
        record["label"]
        for record in merged
    )

    sources = Counter(
        record["source"]
        for record in merged
    )

    categories = Counter(
        record["category"]
        for record in merged
    )

    print("\n=== MERGE SUMMARY ===")
    print(f"Records before deduplication: {before}")
    print(f"Duplicates removed:           {duplicates_removed}")
    print(f"Records after deduplication:  {len(merged)}")

    print("\n=== LABELS ===")
    for label, count in sorted(labels.items()):
        print(f"{label:<30} {count}")

    print("\n=== SOURCES ===")
    for source, count in sorted(sources.items()):
        print(f"{source:<30} {count}")

    print("\n=== CANONICAL CATEGORIES ===")
    for category, count in sorted(categories.items()):
        print(f"{category:<30} {count}")

    print("\n=== OUTPUT ===")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()