"""
Calibrate SemanticGuard's threshold specifically for the
alert-analysis path (LiveAlertInvestigator), separately from the
chat-query threshold calibrated in calibrate_threshold.py.

Uses the SAME reference attack corpus SemanticGuard compares
against at runtime (data/security/prepared/reference.jsonl) -- the
corpus itself is fine, generic prompt-injection phrasing. What
needs recalibrating is the threshold, because formatted alert text
("Security Alert\\nTimestamp: ...") sits at a different distance
from that corpus than casual benign chat does.
"""

import json
from pathlib import Path

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim

PROJECT_ROOT = Path(__file__).resolve().parents[2]

REFERENCE_FILE = (
    PROJECT_ROOT / "data" / "security" / "prepared" / "reference.jsonl"
)
VALIDATION_FILE = (
    PROJECT_ROOT
    / "data"
    / "security"
    / "alert_injection"
    / "validation.jsonl"
)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

THRESHOLDS = [round(0.30 + i * 0.02, 2) for i in range(31)]


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    records: list[dict] = []

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


def calculate_metrics(
    scores: list[float],
    labels: list[str],
    threshold: float,
) -> dict[str, float]:
    tp = fp = tn = fn = 0

    for score, label in zip(scores, labels):
        predicted_attack = score >= threshold
        actual_attack = label == "attack"

        if predicted_attack and actual_attack:
            tp += 1
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and not actual_attack:
            tn += 1
        else:
            fn += 1

    total_attacks = tp + fn
    total_benign = tn + fp

    detection_rate = tp / total_attacks if total_attacks else 0.0
    false_positive_rate = fp / total_benign if total_benign else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = detection_rate
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    accuracy = (tp + tn) / len(labels) if labels else 0.0

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def find_best_threshold(
    scores: list[float],
    labels: list[str],
) -> tuple[float, dict[str, float]]:
    """
    Select the lowest-FPR threshold that still achieves 100%
    detection on the attack set, falling back to best F1 if no
    threshold reaches full detection.

    For a guard sitting in front of a live analyst pipeline, zero
    false positives on routine alerts matters as much as catching
    the injection -- an SSH login and log injection landing on
    opposite sides of the line is the actual requirement here, not
    just the best average score.
    """

    candidates = [
        (t, calculate_metrics(scores, labels, t)) for t in THRESHOLDS
    ]

    full_detection = [
        (t, m) for t, m in candidates if m["detection_rate"] == 1.0
    ]

    if full_detection:
        return min(full_detection, key=lambda item: item[1]["false_positive_rate"])

    return max(
        candidates,
        key=lambda item: (
            item[1]["f1"],
            item[1]["detection_rate"],
            -item[1]["false_positive_rate"],
        ),
    )


def main() -> None:
    print("\n=== ALERT-TEXT SEMANTIC GUARD THRESHOLD CALIBRATION ===\n")

    reference = load_jsonl(REFERENCE_FILE)
    validation = load_jsonl(VALIDATION_FILE)

    reference_attacks = [r for r in reference if r["label"] == "attack"]

    print(f"Reference attacks (runtime corpus): {len(reference_attacks)}")
    print(f"Validation records (alert text):    {len(validation)}")

    attack_texts = [r["text"] for r in reference_attacks]
    validation_texts = [r["text"] for r in validation]
    validation_labels = [r["label"] for r in validation]

    print("\nLoading embedding model...")
    model = SentenceTransformer(MODEL_NAME)

    reference_embeddings = model.encode(
        attack_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    validation_embeddings = model.encode(
        validation_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    similarity_matrix = cos_sim(validation_embeddings, reference_embeddings)
    max_scores = similarity_matrix.max(dim=1).values.cpu().tolist()

    attack_scores = [
        s for s, l in zip(max_scores, validation_labels) if l == "attack"
    ]
    benign_scores = [
        s for s, l in zip(max_scores, validation_labels) if l == "benign"
    ]

    print("\n=== SCORE RANGE ===")
    print(f"Attack min:  {min(attack_scores):.4f}")
    print(f"Attack max:  {max(attack_scores):.4f}")
    print(f"Benign min:  {min(benign_scores):.4f}")
    print(f"Benign max:  {max(benign_scores):.4f}")

    print("\n=== THRESHOLD EVALUATION ===\n")
    print(
        f"{'Threshold':<12}{'Detection':<12}{'FPR':<10}"
        f"{'Precision':<12}{'Recall':<10}{'F1':<10}{'Accuracy'}"
    )
    print("-" * 82)

    for threshold in THRESHOLDS:
        m = calculate_metrics(max_scores, validation_labels, threshold)
        print(
            f"{threshold:<12.2f}{m['detection_rate']:<12.2%}"
            f"{m['false_positive_rate']:<10.2%}{m['precision']:<12.2%}"
            f"{m['recall']:<10.2%}{m['f1']:<10.2%}{m['accuracy']:.2%}"
        )

    best_threshold, best_metrics = find_best_threshold(
        max_scores, validation_labels
    )

    print("\n=== SELECTED THRESHOLD ===\n")
    print(f"Selected threshold:   {best_threshold:.2f}")
    print(f"Detection rate:       {best_metrics['detection_rate']:.2%}")
    print(f"False positive rate:  {best_metrics['false_positive_rate']:.2%}")
    print(f"Precision:            {best_metrics['precision']:.2%}")
    print(f"F1-score:             {best_metrics['f1']:.2%}")


if __name__ == "__main__":
    main()
