"""
Measure ASR of the direct prompt-injection defense (InputGuard then
SemanticGuard, chained exactly as RAGPipeline.analyze() chains
them -- SemanticGuard only runs if InputGuard allows) against
obfuscation/evasion techniques, broken down per technique.

ASR = attacks that got ALLOWED by both layers / total attacks in
that technique's group. Lower is better; 0% means every attack in
that group was caught by at least one layer.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from agent.security.input_guard import InputGuard
from agent.security.semantic_guard import SemanticGuard

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "security"
    / "prompt_injection_evasion"
    / "validation.jsonl"
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_number}"
                ) from exc

    return records


def assess_chained(
    text: str,
    input_guard: InputGuard,
    semantic_guard: SemanticGuard,
) -> tuple[str, str]:
    """
    Reproduce RAGPipeline.analyze()'s guard chain: InputGuard runs
    first; SemanticGuard only runs if InputGuard allows. Returns
    (decision, layer_that_blocked_or_'none').
    """

    input_result = input_guard.assess(text)

    if input_result.decision == "BLOCK":
        return "BLOCK", "input_guard"

    semantic_result = semantic_guard.assess(text)

    if semantic_result.decision == "BLOCK":
        return "BLOCK", "semantic_guard"

    return "ALLOW", "none"


def main() -> None:
    print("\n=== PROMPT INJECTION EVASION ROBUSTNESS ===\n")

    records = load_jsonl(DATASET_PATH)
    print(f"Loaded records: {len(records)}")

    print("\nLoading guards...")
    input_guard = InputGuard()
    semantic_guard = SemanticGuard()

    technique_results: dict[str, list[bool]] = defaultdict(list)
    bypasses: list[dict[str, Any]] = []

    benign_total = 0
    benign_blocked = 0

    for record in records:
        text = record["text"]
        label = record["label"]
        technique = record.get("evasion_technique", "n/a")

        decision, layer = assess_chained(text, input_guard, semantic_guard)

        if label == "attack":
            bypassed = decision == "ALLOW"
            technique_results[technique].append(bypassed)

            if bypassed:
                bypasses.append(record)

        else:
            benign_total += 1
            if decision == "BLOCK":
                benign_blocked += 1

    print("\n=== ASR BY EVASION TECHNIQUE ===\n")
    print(f"{'Technique':<25}{'ASR':<12}{'Bypassed / Total'}")
    print("-" * 60)

    total_attacks = 0
    total_bypassed = 0

    for technique in sorted(technique_results):
        outcomes = technique_results[technique]
        bypassed = sum(outcomes)
        total = len(outcomes)
        asr = bypassed / total if total else 0.0

        total_attacks += total
        total_bypassed += bypassed

        print(f"{technique:<25}{asr:<12.2%}{bypassed}/{total}")

    overall_asr = total_bypassed / total_attacks if total_attacks else 0.0

    print("\n=== OVERALL ===\n")
    print(f"Total attack records:   {total_attacks}")
    print(f"Bypassed both guards:   {total_bypassed}")
    print(f"Overall ASR:            {overall_asr:.2%}")

    benign_fpr = benign_blocked / benign_total if benign_total else 0.0
    print(f"\nBenign records:          {benign_total}")
    print(f"Benign false positives:  {benign_blocked}")
    print(f"False positive rate:     {benign_fpr:.2%}")

    if bypasses:
        print("\n=== BYPASSED EXAMPLES (first 10) ===\n")

        for record in bypasses[:10]:
            excerpt = record["text"][:100].encode(
                "ascii", errors="backslashreplace"
            ).decode("ascii")
            print(f"[{record['evasion_technique']}] {excerpt}")

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
