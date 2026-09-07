from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from agent.security.tool_misuse_guard import ToolMisuseGuard


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ROBUSTNESS_PATH = (
    PROJECT_ROOT
    / "data"
    / "security"
    / "tool_misuse"
    / "robustness.jsonl"
)


# ============================================================
# LOAD JSONL
# ============================================================

def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load a JSONL dataset."""

    if not path.exists():
        raise FileNotFoundError(
            f"Robustness dataset not found:\n{path}"
        )

    records: list[dict[str, Any]] = []

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
                record = json.loads(line)

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line "
                    f"{line_number}: {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Line {line_number} must contain "
                    f"a JSON object."
                )

            records.append(record)

    return records


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    y_true: list[str],
    y_pred: list[str],
) -> dict[str, float]:

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for true, pred in zip(
        y_true,
        y_pred,
    ):

        if true == "malicious" and pred == "malicious":
            tp += 1

        elif true == "benign" and pred == "benign":
            tn += 1

        elif true == "benign" and pred == "malicious":
            fp += 1

        elif true == "malicious" and pred == "benign":
            fn += 1

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# ASR
# ============================================================

def calculate_asr(
    malicious_predictions: list[str],
) -> float:

    """
    Attack Success Rate.

    ASR = malicious attacks incorrectly allowed
          --------------------------------------
              total malicious attacks

    Lower is better.
    """

    if not malicious_predictions:
        return 0.0

    successful_attacks = sum(
        prediction == "benign"
        for prediction in malicious_predictions
    )

    return (
        successful_attacks
        / len(malicious_predictions)
    )


# ============================================================
# MAIN BENCHMARK
# ============================================================

def run_robustness_benchmark() -> None:

    print("=" * 70)
    print("TOOL MISUSE GUARD - ROBUSTNESS BENCHMARK")
    print("=" * 70)

    print()
    print(
        f"Dataset: {ROBUSTNESS_PATH}"
    )

    records = load_jsonl(
        ROBUSTNESS_PATH
    )

    if not records:
        print()
        print("[ERROR]")
        print("Robustness dataset is empty.")
        return

    print()
    print(
        f"Loaded records: {len(records)}"
    )

    # --------------------------------------------------------
    # Guard
    # --------------------------------------------------------

    guard = ToolMisuseGuard()

    y_true: list[str] = []
    y_pred: list[str] = []

    malicious_predictions: list[str] = []

    benign_predictions: list[str] = []

    # Per-family storage
    family_true: dict[str, list[str]] = defaultdict(list)
    family_pred: dict[str, list[str]] = defaultdict(list)

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    for record in records:

        record_id = str(
            record.get("id", "unknown")
        )

        label = str(
            record.get("label", "")
        ).strip().lower()

        family = str(
            record.get(
                "attack_family",
                "unknown",
            )
        )

        instruction = str(
            record.get(
                "user_instruction",
                "",
            )
        )

        tool_name = record.get(
            "tool_name"
        )

        tool_parameters = record.get(
            "tool_parameters",
            {},
        )

        if not isinstance(
            tool_parameters,
            dict,
        ):
            tool_parameters = {}

        if label not in {
            "malicious",
            "benign",
        }:
            print(
                f"[WARNING] Skipping {record_id}: "
                f"unknown label '{label}'"
            )
            continue

        # ----------------------------------------------------
        # Guard
        # ----------------------------------------------------

        result = guard.assess(
            user_instruction=instruction,
            tool_name=tool_name,
            tool_parameters=tool_parameters,
        )

        # ----------------------------------------------------
        # Convert decision
        # ----------------------------------------------------

        if result.decision == "BLOCK":
            prediction = "malicious"
        else:
            prediction = "benign"

        y_true.append(label)
        y_pred.append(prediction)

        family_true[family].append(label)
        family_pred[family].append(prediction)

        if label == "malicious":
            malicious_predictions.append(
                prediction
            )

        else:
            benign_predictions.append(
                prediction
            )

    # ========================================================
    # GLOBAL METRICS
    # ========================================================

    metrics = calculate_metrics(
        y_true,
        y_pred,
    )

    asr = calculate_asr(
        malicious_predictions
    )

    attack_detection_rate = 1.0 - asr

    # ========================================================
    # DISPLAY DATASET
    # ========================================================

    print()
    print("=" * 70)
    print("DATASET")
    print("=" * 70)

    print(
        f"Total samples       : {len(y_true)}"
    )

    print(
        f"Malicious samples   : "
        f"{len(malicious_predictions)}"
    )

    print(
        f"Benign samples      : "
        f"{len(benign_predictions)}"
    )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    print()
    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print(
        f"True Positives      : {metrics['tp']}"
    )

    print(
        f"True Negatives      : {metrics['tn']}"
    )

    print(
        f"False Positives     : {metrics['fp']}"
    )

    print(
        f"False Negatives     : {metrics['fn']}"
    )

    # ========================================================
    # GLOBAL METRICS
    # ========================================================

    print()
    print("=" * 70)
    print("GLOBAL METRICS")
    print("=" * 70)

    print(
        f"Accuracy            : "
        f"{metrics['accuracy']:.4f} "
        f"({metrics['accuracy'] * 100:.2f}%)"
    )

    print(
        f"Precision           : "
        f"{metrics['precision']:.4f} "
        f"({metrics['precision'] * 100:.2f}%)"
    )

    print(
        f"Recall              : "
        f"{metrics['recall']:.4f} "
        f"({metrics['recall'] * 100:.2f}%)"
    )

    print(
        f"F1-score            : "
        f"{metrics['f1']:.4f} "
        f"({metrics['f1'] * 100:.2f}%)"
    )

    # ========================================================
    # SECURITY METRICS
    # ========================================================

    print()
    print("=" * 70)
    print("SECURITY / ROBUSTNESS")
    print("=" * 70)

    print(
        f"Attack Detection Rate : "
        f"{attack_detection_rate:.4f} "
        f"({attack_detection_rate * 100:.2f}%)"
    )

    print(
        f"ASR                   : "
        f"{asr:.4f} "
        f"({asr * 100:.2f}%)"
    )

    # ========================================================
    # BENIGN
    # ========================================================

    benign_allowed = sum(
        prediction == "benign"
        for prediction in benign_predictions
    )

    benign_blocked = sum(
        prediction == "malicious"
        for prediction in benign_predictions
    )

    benign_allow_rate = (
        benign_allowed
        / len(benign_predictions)
        if benign_predictions
        else 0.0
    )

    false_positive_rate = (
        benign_blocked
        / len(benign_predictions)
        if benign_predictions
        else 0.0
    )

    print()
    print("=" * 70)
    print("BENIGN REQUESTS")
    print("=" * 70)

    print(
        f"Allowed             : "
        f"{benign_allowed}"
    )

    print(
        f"Blocked             : "
        f"{benign_blocked}"
    )

    print(
        f"Benign Allow Rate   : "
        f"{benign_allow_rate:.4f} "
        f"({benign_allow_rate * 100:.2f}%)"
    )

    print(
        f"False Positive Rate  : "
        f"{false_positive_rate:.4f} "
        f"({false_positive_rate * 100:.2f}%)"
    )

    # ========================================================
    # PER FAMILY
    # ========================================================

    print()
    print("=" * 70)
    print("ROBUSTNESS BY ATTACK FAMILY")
    print("=" * 70)

    for family in sorted(family_true):

        family_labels = family_true[family]
        family_predictions = family_pred[family]

        family_metrics = calculate_metrics(
            family_labels,
            family_predictions,
        )

        family_malicious_predictions = [
            prediction
            for label, prediction
            in zip(
                family_labels,
                family_predictions,
            )
            if label == "malicious"
        ]

        family_asr = calculate_asr(
            family_malicious_predictions
        )

        malicious_count = sum(
            label == "malicious"
            for label in family_labels
        )

        print()
        print(
            f"[{family}]"
        )

        print(
            f"  Samples       : "
            f"{len(family_labels)}"
        )

        print(
            f"  Malicious     : "
            f"{malicious_count}"
        )

        print(
            f"  ASR           : "
            f"{family_asr:.4f} "
            f"({family_asr * 100:.2f}%)"
        )

        print(
            f"  Accuracy      : "
            f"{family_metrics['accuracy'] * 100:.2f}%"
        )

        print(
            f"  Recall        : "
            f"{family_metrics['recall'] * 100:.2f}%"
        )

    # ========================================================
    # FAILED MALICIOUS CASES
    # ========================================================

    print()
    print("=" * 70)
    print("SUCCESSFUL ATTACKS / BYPASSES")
    print("=" * 70)

    bypass_count = 0

    for record in records:

        if (
            str(record.get("label", "")).lower()
            != "malicious"
        ):
            continue

        result = guard.assess(
            user_instruction=str(
                record.get(
                    "user_instruction",
                    "",
                )
            ),
            tool_name=record.get(
                "tool_name"
            ),
            tool_parameters=(
                record.get(
                    "tool_parameters",
                    {},
                )
                if isinstance(
                    record.get(
                        "tool_parameters",
                        {},
                    ),
                    dict,
                )
                else {}
            ),
        )

        if result.decision == "ALLOW":

            bypass_count += 1

            print()
            print(
                f"ID              : "
                f"{record.get('id')}"
            )

            print(
                f"Family          : "
                f"{record.get('attack_family')}"
            )

            print(
                f"Instruction     : "
                f"{record.get('user_instruction')}"
            )

            print(
                f"Tool            : "
                f"{record.get('tool_name')}"
            )

            print(
                f"Risk score      : "
                f"{result.risk_score:.4f}"
            )

    if bypass_count == 0:
        print(
            "No successful attack bypass detected."
        )

    # ========================================================
    # FALSE POSITIVES
    # ========================================================

    print()
    print("=" * 70)
    print("FALSE POSITIVES")
    print("=" * 70)

    false_positive_count = 0

    for record in records:

        if (
            str(record.get("label", "")).lower()
            != "benign"
        ):
            continue

        result = guard.assess(
            user_instruction=str(
                record.get(
                    "user_instruction",
                    "",
                )
            ),
            tool_name=record.get(
                "tool_name"
            ),
            tool_parameters=(
                record.get(
                    "tool_parameters",
                    {},
                )
                if isinstance(
                    record.get(
                        "tool_parameters",
                        {},
                    ),
                    dict,
                )
                else {}
            ),
        )

        if result.decision == "BLOCK":

            false_positive_count += 1

            print()
            print(
                f"ID              : "
                f"{record.get('id')}"
            )

            print(
                f"Instruction     : "
                f"{record.get('user_instruction')}"
            )

            print(
                f"Tool            : "
                f"{record.get('tool_name')}"
            )

            print(
                f"Risk score      : "
                f"{result.risk_score:.4f}"
            )

            print(
                f"Matched attack  : "
                f"{result.matched_attack}"
            )

            print(
                f"Matched tool    : "
                f"{result.matched_tool}"
            )

    if false_positive_count == 0:
        print(
            "No false positive detected."
        )

    # ========================================================
    # FINAL
    # ========================================================

    print()
    print("=" * 70)
    print("ROBUSTNESS BENCHMARK COMPLETED")
    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:
        run_robustness_benchmark()

    except FileNotFoundError as exc:

        print()
        print("[ERROR]")
        print(str(exc))

        raise SystemExit(1)

    except Exception as exc:

        print()
        print("[ERROR]")
        print(
            f"Benchmark failed: {exc}"
        )

        raise SystemExit(1)