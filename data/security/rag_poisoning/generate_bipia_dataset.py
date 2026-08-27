import json
import random
from pathlib import Path


BIPIA_DIR = Path(
    "data/external/bipia/raw/BIPIA-main/benchmark"
)

OUTPUT_DIR = Path(
    "data/security/rag_poisoning/bipia"
)

SEED = 42

SCENARIOS = {
    "email": BIPIA_DIR / "email" / "train.jsonl",
    "code": BIPIA_DIR / "code" / "train.jsonl",
}

ATTACK_FILE = (
    BIPIA_DIR / "text_attack_train.json"
)


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL records."""

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    records: list[dict] = []

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
                    f"Invalid JSON at "
                    f"{path}:{line_number}"
                ) from exc

    return records


def load_attacks(path: Path) -> list[dict]:
    """Load BIPIA attacks while preserving native families."""

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    attacks: list[dict] = []

    for family, attack_list in data.items():
        for attack_index, attack in enumerate(
            attack_list
        ):
            attacks.append(
                {
                    "family": family,
                    "attack_index": attack_index,
                    "attack_text": str(attack),
                }
            )

    return attacks


def normalize_context(
    record: dict,
    scenario: str,
) -> dict:
    """
    Normalize BIPIA task information.

    Email:
        task = question

    Code:
        task = error
    """

    context = str(
        record.get("context", "")
    ).strip()

    if not context:
        raise ValueError(
            f"{scenario} context is empty."
        )

    if scenario == "email":
        task = str(
            record.get("question", "")
        ).strip()

    elif scenario == "code":
        errors = record.get(
            "error",
            [],
        )

        if isinstance(errors, list):
            task = "\n".join(
                str(error).strip()
                for error in errors
                if str(error).strip()
            )
        else:
            task = str(errors).strip()

    else:
        raise ValueError(
            f"Unsupported scenario: {scenario}"
        )

    ideal = record.get(
        "ideal",
        "",
    )

    if isinstance(ideal, list):
        ideal = "\n".join(
            str(item)
            for item in ideal
        )

    return {
        "context": context,
        "task": str(ideal).strip() and task or task,
        "ideal": str(ideal),
    }


def insert_start(
    context: str,
    attack: str,
) -> str:
    """Insert attack at the beginning."""

    return f"{attack}\n{context}"


def insert_end(
    context: str,
    attack: str,
) -> str:
    """Insert attack at the end."""

    return f"{context}\n{attack}"


def insert_middle(
    context: str,
    attack: str,
) -> str:
    """Insert attack approximately in the middle."""

    words = context.split()

    if len(words) < 4:
        return insert_end(
            context,
            attack,
        )

    middle = len(words) // 2

    before = " ".join(
        words[:middle]
    )

    after = " ".join(
        words[middle:]
    )

    return (
        f"{before}\n"
        f"{attack}\n"
        f"{after}"
    )


INSERT_FUNCTIONS = {
    "start": insert_start,
    "middle": insert_middle,
    "end": insert_end,
}


def build_clean_record(
    record: dict,
    scenario: str,
    context_index: int,
) -> dict:
    """Create one clean record."""

    normalized = normalize_context(
        record,
        scenario,
    )

    pair_id = (
        f"bipia_{scenario}_pair_"
        f"{context_index:04d}"
    )

    return {
        "id": (
            f"bipia_{scenario}_clean_"
            f"{context_index:04d}"
        ),
        "pair_id": pair_id,
        "context": normalized["context"],
        "task": normalized["task"],
        "ideal": normalized["ideal"],
        "label": "clean",
        "category": scenario,
        "source": "BIPIA",
        "source_split": "train",
        "scenario": scenario,
        "context_index": context_index,
    }


def build_poisoned_record(
    record: dict,
    scenario: str,
    context_index: int,
    attack: dict,
    position: str,
) -> dict:
    """Create the poisoned partner of a clean record."""

    normalized = normalize_context(
        record,
        scenario,
    )

    pair_id = (
        f"bipia_{scenario}_pair_"
        f"{context_index:04d}"
    )

    poisoned_context = INSERT_FUNCTIONS[
        position
    ](
        normalized["context"],
        attack["attack_text"],
    )

    return {
        "id": (
            f"bipia_{scenario}_poisoned_"
            f"{context_index:04d}"
        ),
        "pair_id": pair_id,
        "context": poisoned_context,
        "task": normalized["task"],
        "ideal": normalized["ideal"],
        "label": "poisoned",
        "category": "indirect_injection",
        "source": "BIPIA",
        "source_split": "train",
        "scenario": scenario,
        "context_index": context_index,
        "attack_family": attack["family"],
        "attack_index": attack["attack_index"],
        "attack_text": attack["attack_text"],
        "position": position,
    }


def write_jsonl(
    records: list[dict],
    path: Path,
) -> None:
    """Write records as JSONL."""

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in records:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )


def main() -> None:
    """Generate exactly 100 clean/poisoned pairs."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rng = random.Random(SEED)

    attacks = load_attacks(
        ATTACK_FILE
    )

    all_clean: list[dict] = []
    all_poisoned: list[dict] = []

    positions = [
        "start",
        "middle",
        "end",
    ]

    global_pair_index = 0

    print(
        "\n=== BIPIA PAIRED DATASET GENERATION ===\n"
    )

    print(
        f"Attack strings: {len(attacks)}"
    )

    # Shuffle attacks once so all families can participate.
    shuffled_attacks = attacks.copy()
    rng.shuffle(shuffled_attacks)

    for scenario, path in SCENARIOS.items():
        contexts = load_jsonl(path)

        print(
            f"{scenario:<10}: "
            f"{len(contexts)} contexts"
        )

        for context_index, record in enumerate(
            contexts
        ):
            global_pair_index += 1

            # Each original context is used exactly once.
            attack = shuffled_attacks[
                (global_pair_index - 1)
                % len(shuffled_attacks)
            ]

            # Rotate positions to obtain balanced coverage.
            position = positions[
                (global_pair_index - 1)
                % len(positions)
            ]

            clean_record = build_clean_record(
                record,
                scenario,
                context_index,
            )

            poisoned_record = build_poisoned_record(
                record,
                scenario,
                context_index,
                attack,
                position,
            )

            all_clean.append(
                clean_record
            )

            all_poisoned.append(
                poisoned_record
            )

    clean_path = (
        OUTPUT_DIR / "clean.jsonl"
    )

    poisoned_path = (
        OUTPUT_DIR / "poisoned.jsonl"
    )

    metadata_path = (
        OUTPUT_DIR / "metadata.json"
    )

    write_jsonl(
        all_clean,
        clean_path,
    )

    write_jsonl(
        all_poisoned,
        poisoned_path,
    )

    metadata = {
        "source": "BIPIA",
        "source_split": "train",
        "seed": SEED,
        "paired": True,
        "total_pairs": len(all_clean),
        "clean_records": len(all_clean),
        "poisoned_records": len(all_poisoned),
        "scenarios": {
            "email": sum(
                r["scenario"] == "email"
                for r in all_clean
            ),
            "code": sum(
                r["scenario"] == "code"
                for r in all_clean
            ),
        },
        "positions": {
            position: sum(
                r["position"] == position
                for r in all_poisoned
            )
            for position in positions
        },
        "note": (
            "Each clean context has exactly one poisoned "
            "partner. The task/query remains identical."
        ),
    }

    with metadata_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            ensure_ascii=False,
            indent=2,
        )

    print("\n=== SUMMARY ===")
    print(
        f"Clean records:    {len(all_clean)}"
    )
    print(
        f"Poisoned records: {len(all_poisoned)}"
    )
    print(
        f"Pairs:            {len(all_clean)}"
    )

    print(
        "\n=== POSITIONS ==="
    )

    for position, count in metadata[
        "positions"
    ].items():
        print(
            f"{position:<10} {count}"
        )

    print(
        f"\nOutput: {OUTPUT_DIR}"
    )


if __name__ == "__main__":
    main()