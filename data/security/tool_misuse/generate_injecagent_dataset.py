from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

SOURCE_DIR = (
    ROOT
    / "external"
    / "injecagent"
    / "InjecAgent"
    / "data"
)

OUTPUT_DIR = (
    ROOT
    / "security"
    / "tool_misuse"
    / "injecagent"
)


def load_json(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array."""
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list: {path}")

    return data


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL records."""
    records = []

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

            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected object at {path}:{line_number}"
                )

            records.append(record)

    return records


def normalize_text(value: Any) -> str:
    """Convert a value to clean text."""
    if value is None:
        return ""

    if isinstance(value, str):
        return " ".join(value.split())

    return str(value)


def build_attack_record(
    record: dict[str, Any],
    attack_type: str,
    index: int,
) -> dict[str, Any]:
    """Convert an InjecAgent attacker case into our format."""

    attacker_instruction = normalize_text(
        record.get("Attacker Instruction")
    )

    attacker_tools = record.get(
        "Attacker Tools",
        [],
    )

    expected_achievements = normalize_text(
        record.get("Expected Achievements")
    )

    modified = record.get(
        "Modifed",
        0,
    )

    return {
        "id": f"injecagent_{attack_type}_{index:04d}",
        "text": attacker_instruction,
        "label": "tool_misuse",
        "category": "indirect_tool_attack",
        "source": "InjecAgent",
        "attack_type": normalize_text(
            record.get("Attack Type")
        ),
        "attacker_tools": attacker_tools,
        "expected_achievements": expected_achievements,
        "modified": modified,
    }


def build_user_record(
    record: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    """Convert an InjecAgent user case into our format."""

    user_instruction = normalize_text(
        record.get("User Instruction")
    )

    user_tool = normalize_text(
        record.get("User Tool")
    )

    thought = normalize_text(
        record.get("Thought")
    )

    return {
        "id": f"injecagent_user_{index:04d}",
        "text": user_instruction,
        "label": "benign",
        "category": "tool_use",
        "source": "InjecAgent",
        "level": record.get("Level"),
        "thought": thought,
        "user_tool": user_tool,
        "tool_parameters": record.get(
            "Tool Parameters"
        ),
        "tool_response_template": normalize_text(
            record.get("Tool Response Template")
        ),
    }


def write_jsonl(
    path: Path,
    records: list[dict[str, Any]],
) -> None:
    """Write records as UTF-8 JSONL."""

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
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
    print("=== INJECAGENT TOOL MISUSE DATASET GENERATION ===")
    print()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    direct_harm_path = (
        SOURCE_DIR / "attacker_cases_dh.jsonl"
    )

    data_stealing_path = (
        SOURCE_DIR / "attacker_cases_ds.jsonl"
    )

    user_cases_path = (
        SOURCE_DIR / "user_cases.jsonl"
    )

    direct_harm = load_jsonl(
        direct_harm_path
    )

    data_stealing = load_jsonl(
        data_stealing_path
    )

    user_cases = load_jsonl(
        user_cases_path
    )

    print(
        f"Direct harm attacks:   {len(direct_harm)}"
    )
    print(
        f"Data stealing attacks: {len(data_stealing)}"
    )
    print(
        f"Total attacks:         "
        f"{len(direct_harm) + len(data_stealing)}"
    )
    print(
        f"User cases:            {len(user_cases)}"
    )
    print()

    attack_records = []

    for index, record in enumerate(
        direct_harm,
        start=1,
    ):
        attack_records.append(
            build_attack_record(
                record,
                "direct_harm",
                index,
            )
        )

    for index, record in enumerate(
        data_stealing,
        start=1,
    ):
        attack_records.append(
            build_attack_record(
                record,
                "data_stealing",
                index,
            )
        )

    user_records = [
        build_user_record(
            record,
            index,
        )
        for index, record in enumerate(
            user_cases,
            start=1,
        )
    ]

    attacks_output = (
        OUTPUT_DIR
        / "attacks.jsonl"
    )

    benign_output = (
        OUTPUT_DIR
        / "benign.jsonl"
    )

    metadata_output = (
        OUTPUT_DIR
        / "metadata.json"
    )

    write_jsonl(
        attacks_output,
        attack_records,
    )

    write_jsonl(
        benign_output,
        user_records,
    )

    attack_types = {}

    for record in attack_records:
        attack_type = record["attack_type"]

        attack_types[attack_type] = (
            attack_types.get(
                attack_type,
                0,
            )
            + 1
        )

    tools = set()

    for record in attack_records:
        for tool in record["attacker_tools"]:
            tools.add(
                normalize_text(tool)
            )

    metadata = {
        "source": "InjecAgent",
        "dataset_type": "tool_misuse",
        "attack_records": len(
            attack_records
        ),
        "benign_records": len(
            user_records
        ),
        "total_records": (
            len(attack_records)
            + len(user_records)
        ),
        "direct_harm": len(
            direct_harm
        ),
        "data_stealing": len(
            data_stealing
        ),
        "attack_types": attack_types,
        "unique_attacker_tools": len(
            tools
        ),
    }

    with metadata_output.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print("=== SUMMARY ===")
    print(
        f"Attack records:  "
        f"{len(attack_records)}"
    )
    print(
        f"Benign records:  "
        f"{len(user_records)}"
    )
    print(
        f"Total records:   "
        f"{len(attack_records) + len(user_records)}"
    )
    print()
    print(
        f"Unique tools used by attacks: "
        f"{len(tools)}"
    )
    print()
    print(
        f"Output directory: "
        f"{OUTPUT_DIR}"
    )
    print()
    print("=== DONE ===")


if __name__ == "__main__":
    main()