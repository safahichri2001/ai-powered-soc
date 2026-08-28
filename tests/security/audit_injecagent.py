import json
from collections import Counter
from pathlib import Path


DATA_DIR = Path(
    "data/external/injecagent/InjecAgent/data"
)


def load_json(path: Path):
    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def load_jsonl(path: Path):
    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for line in f:
            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return records


def print_keys(records, name):
    if not records:
        print(f"{name}: empty")
        return

    keys = set()

    for record in records:
        keys.update(record.keys())

    print(f"{name} keys:")
    for key in sorted(keys):
        print(f"  - {key}")


def main():

    print("=== INJECAGENT DATASET AUDIT ===")
    print()

    # --------------------------------------------------
    # Attacker cases
    # --------------------------------------------------

    dh = load_jsonl(
        DATA_DIR / "attacker_cases_dh.jsonl"
    )

    ds = load_jsonl(
        DATA_DIR / "attacker_cases_ds.jsonl"
    )

    user_cases = load_jsonl(
        DATA_DIR / "user_cases.jsonl"
    )

    print("=== ATTACKER CASES ===")
    print(f"Direct Harm:       {len(dh)}")
    print(f"Data Stealing:     {len(ds)}")
    print(f"Total attacker:    {len(dh) + len(ds)}")
    print()

    print_keys(
        dh,
        "Direct Harm"
    )

    print()

    print_keys(
        ds,
        "Data Stealing"
    )

    print()

    # --------------------------------------------------
    # User cases
    # --------------------------------------------------

    print("=== USER CASES ===")
    print(f"User cases: {len(user_cases)}")
    print()

    print_keys(
        user_cases,
        "User cases"
    )

    print()

    # --------------------------------------------------
    # Test cases
    # --------------------------------------------------

    test_files = [
        "test_cases_dh_base.json",
        "test_cases_dh_enhanced.json",
        "test_cases_ds_base.json",
        "test_cases_ds_enhanced.json",
    ]

    print("=== TEST CASES ===")

    test_data = {}

    for filename in test_files:
        records = load_json(
            DATA_DIR / filename
        )

        test_data[filename] = records

        print(
            f"{filename:<35} {len(records)}"
        )

    print()

    # --------------------------------------------------
    # Tools
    # --------------------------------------------------

    tools = load_json(
        DATA_DIR / "tools.json"
    )

    print("=== TOOLS ===")
    print(f"Tools: {len(tools)}")
    print()

    if tools:
        print_keys(
            tools,
            "Tools"
        )

    print()

    # --------------------------------------------------
    # Attack distributions
    # --------------------------------------------------

    print("=== ATTACK CASE STRUCTURE ===")

    all_attacks = [
        ("direct_harm", record)
        for record in dh
    ] + [
        ("data_stealing", record)
        for record in ds
    ]

    attack_keys = Counter()

    for category, record in all_attacks:
        for key in record.keys():
            attack_keys[key] += 1

    for key, count in attack_keys.most_common():
        print(
            f"{key:<30} {count}"
        )

    print()

    # --------------------------------------------------
    # Sample attacks
    # --------------------------------------------------

    print("=== SAMPLE ATTACKS ===")

    for category, record in all_attacks[:5]:

        print()
        print(f"[{category}]")

        for key, value in record.items():

            if isinstance(value, str):
                value = value.replace(
                    "\n",
                    " "
                )

                if len(value) > 300:
                    value = value[:300] + "..."

            print(
                f"{key}: {value}"
            )

    print()

    # --------------------------------------------------
    # Duplicate attacker cases
    # --------------------------------------------------

    print("=== DUPLICATES ===")

    attack_texts = []

    for _, record in all_attacks:

        for key in (
            "attack",
            "attack_instruction",
            "text",
            "content",
            "instruction",
        ):
            value = record.get(key)

            if isinstance(value, str):
                attack_texts.append(
                    value.strip()
                )

    duplicates = (
        len(attack_texts)
        - len(set(attack_texts))
    )

    print(
        f"Attack text candidates: {len(attack_texts)}"
    )

    print(
        f"Duplicate attack texts: {duplicates}"
    )

    print()

    # --------------------------------------------------
    # Base vs enhanced
    # --------------------------------------------------

    print("=== BASE VS ENHANCED ===")

    comparisons = [
        (
            "test_cases_dh_base.json",
            "test_cases_dh_enhanced.json",
        ),
        (
            "test_cases_ds_base.json",
            "test_cases_ds_enhanced.json",
        ),
    ]

    for base_name, enhanced_name in comparisons:

        base = test_data[base_name]
        enhanced = test_data[enhanced_name]

        print()
        print(
            f"{base_name} vs {enhanced_name}"
        )

        print(
            f"Base:     {len(base)}"
        )

        print(
            f"Enhanced: {len(enhanced)}"
        )

        if base and enhanced:

            print(
                "Base first record keys:",
                sorted(base[0].keys()),
            )

            print(
                "Enhanced first record keys:",
                sorted(enhanced[0].keys()),
            )

    print()
    print("=== DONE ===")


if __name__ == "__main__":
    main()