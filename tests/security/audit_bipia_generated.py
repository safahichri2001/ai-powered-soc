
import json
from collections import Counter
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
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line "
                    f"{line_number}"
                ) from exc

    return records


def main() -> None:
    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    all_records = clean + poisoned

    print("\n=== BIPIA GENERATED DATASET AUDIT ===\n")

    print(
        f"Clean records:    {len(clean)}"
    )
    print(
        f"Poisoned records: {len(poisoned)}"
    )
    print(
        f"Total records:    {len(all_records)}"
    )

    print("\n=== LABELS ===")

    labels = Counter(
        r["label"]
        for r in all_records
    )

    for label, count in sorted(
        labels.items()
    ):
        print(
            f"{label:<15} {count}"
        )

    print("\n=== SCENARIOS ===")

    scenarios = Counter(
        r["scenario"]
        for r in all_records
    )

    for scenario, count in sorted(
        scenarios.items()
    ):
        print(
            f"{scenario:<15} {count}"
        )

    print("\n=== ATTACK FAMILIES ===")

    families = Counter(
        r.get("attack_family", "NONE")
        for r in poisoned
    )

    for family, count in sorted(
        families.items()
    ):
        print(
            f"{family:<35} {count}"
        )

    print("\n=== POSITIONS ===")

    positions = Counter(
        r.get("position", "NONE")
        for r in poisoned
    )

    for position, count in sorted(
        positions.items()
    ):
        print(
            f"{position:<15} {count}"
        )

    print("\n=== CONTEXT REUSE ===")

    clean_contexts = Counter(
        r["context_index"]
        for r in clean
    )

    poisoned_contexts = Counter(
        r["context_index"]
        for r in poisoned
    )

    print(
        f"Unique clean contexts: "
        f"{len(clean_contexts)}"
    )

    print(
        f"Unique poisoned contexts: "
        f"{len(poisoned_contexts)}"
    )

    max_reuse = (
        max(poisoned_contexts.values())
        if poisoned_contexts
        else 0
    )

    print(
        f"Maximum poisoned variants "
        f"per context: {max_reuse}"
    )

    print("\n=== DUPLICATE POISONED TEXT ===")

    poisoned_texts = [
        r["context"]
        for r in poisoned
    ]

    duplicates = (
        len(poisoned_texts)
        - len(set(poisoned_texts))
    )

    print(
        f"Duplicate poisoned contexts: "
        f"{duplicates}"
    )

    print("\n=== ATTACK / POSITION ===")

    combinations = Counter(
        (
            r["attack_family"],
            r["position"],
        )
        for r in poisoned
    )

    for (
        family,
        position,
    ), count in sorted(
        combinations.items()
    ):
        print(
            f"{family:<35}"
            f"{position:<10}"
            f"{count}"
        )

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()