import csv
import json
from pathlib import Path


SOURCE_FILE = (
    Path(__file__).parents[1]
    / "external"
    / "prompt_injection_benchmark.csv"
)

OUTPUT_DIR = Path(__file__).parent / "external"
OUTPUT_FILE = OUTPUT_DIR / "prompt_injection_benchmark.jsonl"

SOURCE_NAME = "prompt_injection_benchmark"


def normalize_label(label: str) -> str:
    """Map source labels to our standard labels."""

    label = label.strip().lower()

    mapping = {
        "injection": "attack",
        "benign": "benign",
    }

    if label not in mapping:
        raise ValueError(f"Unknown label: {label}")

    return mapping[label]


def convert_dataset() -> None:
    """Convert the external CSV to the project's JSONL schema."""

    if not SOURCE_FILE.exists():
        raise FileNotFoundError(
            f"Source dataset not found: {SOURCE_FILE}"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, object]] = []

    with SOURCE_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        required_columns = {
            "text",
            "label",
            "category",
            "severity",
        }

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(
                "CSV is missing required columns: "
                f"{required_columns}"
            )

        for index, row in enumerate(reader, start=1):
            text = (row["text"] or "").strip()

            if not text:
                raise ValueError(
                    f"Empty prompt at CSV row {index}"
                )

            records.append(
                {
                    "id": f"ext_{index:03d}",
                    "text": text,
                    "category": row["category"].strip(),
                    "label": normalize_label(row["label"]),
                    "severity": row["severity"].strip().lower(),
                    "source": SOURCE_NAME,
                    "source_id": f"csv_row_{index}",
                }
            )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        for record in records:
            output_file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    print("=== CONVERSION COMPLETE ===")
    print(f"Input : {SOURCE_FILE}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Records converted: {len(records)}")


if __name__ == "__main__":
    convert_dataset()