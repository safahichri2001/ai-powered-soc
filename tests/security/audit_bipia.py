import json
from collections import Counter
from pathlib import Path


BIPIA_DIR = Path(
    "data/external/bipia/raw/BIPIA-main/benchmark"
)


def load_json(path: Path):
    """Load a JSON file."""

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def count_jsonl(path: Path) -> int:
    """Count valid non-empty JSONL records."""

    count = 0

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            if line.strip():
                json.loads(line)
                count += 1

    return count


def main() -> None:
    """Audit BIPIA benchmark structure."""

    print("\n=== BIPIA AUDIT ===\n")

    # ---------------------------------------------------------
    # Context datasets
    # ---------------------------------------------------------

    context_files = [
        BIPIA_DIR / "email" / "train.jsonl",
        BIPIA_DIR / "email" / "test.jsonl",
        BIPIA_DIR / "code" / "train.jsonl",
        BIPIA_DIR / "code" / "test.jsonl",
        BIPIA_DIR / "table" / "train.jsonl",
        BIPIA_DIR / "table" / "test.jsonl",
    ]

    print("=== CONTEXT DATASETS ===")

    for path in context_files:
        if path.exists():
            print(
                f"{path.parent.name:>8} "
                f"{path.stem:<6} "
                f"{count_jsonl(path):>4}"
            )

    # ---------------------------------------------------------
    # Text attacks
    # ---------------------------------------------------------

    print("\n=== TEXT ATTACKS ===")

    for split in (
        "train",
        "test",
    ):
        path = BIPIA_DIR / f"text_attack_{split}.json"

        attacks = load_json(path)

        total_attacks = 0

        print(f"\n{split.upper()}:")

        for task_name, attack_list in attacks.items():
            count = len(attack_list)
            total_attacks += count

            print(
                f"{task_name:<30} {count}"
            )

        print(
            f"TOTAL ATTACK STRINGS: {total_attacks}"
        )

    # ---------------------------------------------------------
    # Attack IDs / duplicate check
    # ---------------------------------------------------------

    print("\n=== ATTACK DUPLICATES ===")

    all_attacks: list[str] = []

    for split in (
        "train",
        "test",
    ):
        attacks = load_json(
            BIPIA_DIR
            / f"text_attack_{split}.json"
        )

        for attack_list in attacks.values():
            all_attacks.extend(
                attack_list
            )

    normalized = [
        " ".join(
            attack.strip().lower().split()
        )
        for attack in all_attacks
    ]

    duplicates = (
        len(normalized)
        - len(set(normalized))
    )

    print(
        f"Total attack strings: {len(all_attacks)}"
    )

    print(
        f"Duplicate attack strings: {duplicates}"
    )

    # ---------------------------------------------------------
    # Sample attack strings
    # ---------------------------------------------------------

    print("\n=== SAMPLE ATTACKS ===")

    attacks = load_json(
        BIPIA_DIR
        / "text_attack_train.json"
    )

    shown = 0

    for task_name, attack_list in attacks.items():
        for attack in attack_list:
            print(
                f"[{task_name}] {attack}"
            )

            shown += 1

            if shown >= 10:
                break

        if shown >= 10:
            break

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()