from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.security.tool_misuse_guard import ToolMisuseGuard


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BENCHMARK_PATH = (
    PROJECT_ROOT
    / "data"
    / "security"
    / "tool_misuse"
    / "benchmark.jsonl"
)


# ============================================================
# DATA LOADING
# ============================================================

def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """
    Load a JSONL file.

    Each line must contain one JSON object.
    Empty lines are ignored.
    """

    if not path.exists():
        raise FileNotFoundError(
            f"Benchmark file not found:\n{path}"
        )

    records: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} "
                    f"of {path.name}: {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Line {line_number} must contain "
                    f"a JSON object."
                )

            records.append(record)

    return records


# ============================================================
# CLASSIFICATION METRICS
# ============================================================

def calculate_metrics(
    y_true: list[str],
    y_pred: list[str],
) -> dict[str, float]:

    if len(y_true) != len(y_pred):
        raise ValueError(
            "y_true and y_pred must have the same length."
        )

    if not y_true:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
        }

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for true, pred in zip(y_true, y_pred):

        true_malicious = true == "malicious"
        pred_malicious = pred == "malicious"

        if true_malicious and pred_malicious:
            true_positive += 1

        elif not true_malicious and not pred_malicious:
            true_negative += 1

        elif not true_malicious and pred_malicious:
            false_positive += 1

        elif true_malicious and not pred_malicious:
            false_negative += 1

    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (true_positive + true_negative) / total
        if total
        else 0.0
    )

    precision = (
        true_positive
        / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    recall = (
        true_positive
        / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# ASR
# ============================================================

def calculate_asr(
    malicious_records: list[dict[str, Any]],
    malicious_predictions: list[str],
) -> float:

    """
    Attack Success Rate (ASR)

    ASR measures the percentage of malicious attacks
    that successfully bypass the security guard.

        ASR = malicious attacks incorrectly ALLOWED
              ------------------------------------
                    total malicious attacks

    Therefore:

        ASR = 0%   -> ideal
        ASR = 100% -> all attacks bypassed the guard
    """

    if not malicious_records:
        return 0.0

    successful_attacks = sum(
        1
        for prediction in malicious_predictions
        if prediction == "benign"
    )

    return successful_attacks / len(malicious_records)


# ============================================================
# BENCHMARK
# ============================================================

def run_benchmark() -> None:

    print("=" * 70)
    print("TOOL MISUSE GUARD BENCHMARK")
    print("=" * 70)

    print()
    print(f"Benchmark: {BENCHMARK_PATH}")

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    records = load_jsonl(BENCHMARK_PATH)

    if not records:
        print("\n[ERROR]")
        print("benchmark.jsonl is empty.")
        return

    print()
    print(f"Loaded records: {len(records)}")

    # --------------------------------------------------------
    # Guard
    # --------------------------------------------------------

    guard = ToolMisuseGuard()

    y_true: list[str] = []
    y_pred: list[str] = []

    malicious_records: list[dict[str, Any]] = []
    malicious_predictions: list[str] = []

    benign_records: list[dict[str, Any]] = []
    benign_predictions: list[str] = []

    # --------------------------------------------------------
    # Evaluation
    # --------------------------------------------------------

    for record in records:

        label = str(
            record.get("label", "")
        ).strip().lower()

        user_instruction = str(
            record.get("user_instruction", "")
        )

        tool_name = record.get(
            "tool_name"
        )

        tool_parameters = record.get(
            "tool_parameters",
            {},
        )

        if not isinstance(tool_parameters, dict):
            tool_parameters = {}

        # ----------------------------------------------------
        # Expected label
        # ----------------------------------------------------

        if label not in {
            "malicious",
            "benign",
        }:
            print(
                f"[WARNING] Unknown label: {label}"
            )
            continue

        # ----------------------------------------------------
        # Guard assessment
        # ----------------------------------------------------

        result = guard.assess(
            user_instruction=user_instruction,
            tool_name=tool_name,
            tool_parameters=tool_parameters,
        )

        # ----------------------------------------------------
        # Convert guard decision to classification
        # ----------------------------------------------------

        if result.decision == "BLOCK":
            prediction = "malicious"
        else:
            prediction = "benign"

        y_true.append(label)
        y_pred.append(prediction)

        # ----------------------------------------------------
        # Separate malicious / benign
        # ----------------------------------------------------

        if label == "malicious":

            malicious_records.append(record)
            malicious_predictions.append(prediction)

        else:

            benign_records.append(record)
            benign_predictions.append(prediction)

    # ========================================================
    # GLOBAL METRICS
    # ========================================================

    metrics = calculate_metrics(
        y_true=y_true,
        y_pred=y_pred,
    )

    # ========================================================
    # ASR
    # ========================================================

    asr = calculate_asr(
        malicious_records=malicious_records,
        malicious_predictions=malicious_predictions,
    )

    attack_detection_rate = 1.0 - asr

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    true_positive = sum(
        1
        for true, pred in zip(y_true, y_pred)
        if true == "malicious"
        and pred == "malicious"
    )

    true_negative = sum(
        1
        for true, pred in zip(y_true, y_pred)
        if true == "benign"
        and pred == "benign"
    )

    false_positive = sum(
        1
        for true, pred in zip(y_true, y_pred)
        if true == "benign"
        and pred == "malicious"
    )

    false_negative = sum(
        1
        for true, pred in zip(y_true, y_pred)
        if true == "malicious"
        and pred == "benign"
    )

    # ========================================================
    # DISPLAY RESULTS
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
        f"{len(malicious_records)}"
    )

    print(
        f"Benign samples      : "
        f"{len(benign_records)}"
    )

    print()
    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print(
        f"True Positives      : {true_positive}"
    )

    print(
        f"True Negatives      : {true_negative}"
    )

    print(
        f"False Positives     : {false_positive}"
    )

    print(
        f"False Negatives     : {false_negative}"
    )

    print()
    print("=" * 70)
    print("CLASSIFICATION METRICS")
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

    print()
    print("=" * 70)
    print("SECURITY / ROBUSTNESS METRICS")
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

    print()
    print(
        "Interpretation:"
    )

    print(
        "  ASR = malicious attacks that were ALLOWED."
    )

    print(
        "  Lower ASR is better."
    )

    print(
        "  ASR = 0% means no malicious attack "
        "bypassed the guard."
    )

    print()
    print("=" * 70)
    print("BENIGN REQUESTS")
    print("=" * 70)

    benign_allowed = sum(
        1
        for prediction in benign_predictions
        if prediction == "benign"
    )

    benign_blocked = sum(
        1
        for prediction in benign_predictions
        if prediction == "malicious"
    )

    print(
        f"Allowed             : {benign_allowed}"
    )

    print(
        f"Blocked             : {benign_blocked}"
    )

    benign_allow_rate = (
        benign_allowed / len(benign_records)
        if benign_records
        else 0.0
    )

    print(
        f"Benign Allow Rate   : "
        f"{benign_allow_rate:.4f} "
        f"({benign_allow_rate * 100:.2f}%)"
    )

    print()
    print("=" * 70)
    print("BENCHMARK COMPLETED")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    try:
        run_benchmark()

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