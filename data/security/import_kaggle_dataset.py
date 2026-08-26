import json
from pathlib import Path


SOURCE_FILE = (
    Path(__file__).parents[1]
    / "external"
    / "kaggle_prompt_injection"
    / "raw"
    / "Prompt_INJECTION_And_Benign_DATASET.jsonl"
)

OUTPUT_DIR = Path(__file__).parent / "external"
OUTPUT_FILE = OUTPUT_DIR / "kaggle_prompt_injection.jsonl"

SOURCE_NAME = "kaggle_prompt_injection"


CATEGORY_MAPPING = {
    "code_execution": "tool_or_code_execution",
    "data_leakage": "data_exfiltration",
    "jailbreaking": "jailbreak",
    "role_playing": "role_hijacking",
    "obfuscation": "obfuscation",
    "none": "benign",
}


LABEL_MAPPING = {
    "malicious": "attack",
    "benign": "benign",
}


def load_jsonl(path: Path) -> list[dict]:
    """Load records from a JSONL file."""

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
                    f"Invalid JSON on line {line_number}"
                ) from exc

    return records


def normalize_text(text: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(
        str(text).strip().lower().split()
    )


def normalize_label(label: str) -> str:
    """Map Kaggle labels to canonical labels."""

    normalized = label.strip().lower()

    if normalized not in LABEL_MAPPING:
        raise ValueError(
            f"Unknown Kaggle label: {label}"
        )

    return LABEL_MAPPING[normalized]


def normalize_category(category: str) -> str:
    """Map Kaggle categories to the canonical taxonomy."""

    normalized = category.strip().lower()

    if normalized not in CATEGORY_MAPPING:
        raise ValueError(
            f"Unknown Kaggle category: {category}"
        )

    return CATEGORY_MAPPING[normalized]


def main() -> None:
    """Convert and clean the Kaggle dataset."""

    records = load_jsonl(SOURCE_FILE)

    converted: list[dict] = []
    seen_prompts: set[str] = set()
    duplicates_removed = 0

    for index, record in enumerate(records, start=1):
        required_fields = {
            "id",
            "prompt",
            "label",
            "attack_type",
        }

        missing = required_fields - record.keys()

        if missing:
            raise ValueError(
                f"Record {record.get('id')} is missing: "
                f"{sorted(missing)}"
            )

        text = str(record["prompt"]).strip()

        if not text:
            raise ValueError(
                f"Empty prompt at record {record['id']}"
            )

        normalized_text = normalize_text(text)

        if normalized_text in seen_prompts:
            duplicates_removed += 1
            continue

        seen_prompts.add(normalized_text)

        label = normalize_label(
            str(record["label"])
        )

        category = normalize_category(
            str(record["attack_type"])
        )

        converted.append(
            {
                "id": f"kaggle_{index:03d}",
                "text": text,
                "category": category,
                "label": label,
                "severity": "unknown",
                "source": SOURCE_NAME,
                "source_id": str(record["id"]),
            }
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in converted:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    attack_count = sum(
        record["label"] == "attack"
        for record in converted
    )

    benign_count = sum(
        record["label"] == "benign"
        for record in converted
    )

    print("=== KAGGLE CONVERSION COMPLETE ===")
    print(f"Input records:       {len(records)}")
    print(f"Duplicates removed:  {duplicates_removed}")
    print(f"Output records:      {len(converted)}")
    print(f"Attack records:      {attack_count}")
    print(f"Benign records:      {benign_count}")
    print(f"Output:              {OUTPUT_FILE}")


if __name__ == "__main__":
    main()