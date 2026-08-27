import json
from pathlib import Path


DATA_DIR = Path(
    "data/security/rag_poisoning/bipia"
)


SUSPICIOUS_MARKERS = (
    "Ã",
    "Â",
    "â€",
    "â€¢",
    "ð",
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


def main() -> None:
    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    records = clean + poisoned

    print("\n=== BIPIA TEXT QUALITY CHECK ===\n")
    print(
        f"Total records: {len(records)}"
    )

    suspicious_records = []

    for record in records:
        text = str(
            record["context"]
        )

        markers = [
            marker
            for marker in SUSPICIOUS_MARKERS
            if marker in text
        ]

        if markers:
            suspicious_records.append(
                (
                    record["id"],
                    markers,
                )
            )

    print(
        f"Records with suspicious encoding: "
        f"{len(suspicious_records)}"
    )

    print("\n=== EXAMPLES ===")

    for record_id, markers in suspicious_records[:10]:
        print(
            f"{record_id}: {markers}"
        )

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()