import json
from pathlib import Path

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim


SECURITY_DIR = Path("data/security")
PREPARED_DIR = SECURITY_DIR / "prepared"

REFERENCE_FILE = PREPARED_DIR / "reference.jsonl"
VALIDATION_FILE = PREPARED_DIR / "validation.jsonl"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Thresholds evaluated during calibration.
THRESHOLDS = [
    round(0.30 + i * 0.02, 2)
    for i in range(31)
]


def load_jsonl(path: Path) -> list[dict]:
    """Load records from a JSONL file."""

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    records: list[dict] = []

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

            records.append(record)

    return records


def calculate_metrics(
    scores: list[float],
    labels: list[str],
    threshold: float,
) -> dict[str, float]:
    """
    Calculate binary classification metrics.

    Attack = positive class
    Benign = negative class
    """

    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0

    for score, label in zip(scores, labels):
        predicted_attack = score >= threshold
        actual_attack = label == "attack"

        if predicted_attack and actual_attack:
            true_positive += 1

        elif predicted_attack and not actual_attack:
            false_positive += 1

        elif not predicted_attack and not actual_attack:
            true_negative += 1

        elif not predicted_attack and actual_attack:
            false_negative += 1

    total_attacks = true_positive + false_negative
    total_benign = true_negative + false_positive

    detection_rate = (
        true_positive / total_attacks
        if total_attacks
        else 0.0
    )

    false_positive_rate = (
        false_positive / total_benign
        if total_benign
        else 0.0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    recall = detection_rate

    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    accuracy = (
        (true_positive + true_negative)
        / len(labels)
        if labels
        else 0.0
    )

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "recall": recall,
        "f1": f1_score,
        "accuracy": accuracy,
    }


def find_best_threshold(
    scores: list[float],
    labels: list[str],
) -> tuple[float, dict[str, float]]:
    """
    Select the threshold that maximizes F1.

    Tie-breaking:
    1. Higher detection rate
    2. Lower false positive rate
    """

    candidates: list[
        tuple[float, dict[str, float]]
    ] = []

    for threshold in THRESHOLDS:
        metrics = calculate_metrics(
            scores,
            labels,
            threshold,
        )

        candidates.append(
            (threshold, metrics)
        )

    best_threshold, best_metrics = max(
        candidates,
        key=lambda item: (
            item[1]["f1"],
            item[1]["detection_rate"],
            -item[1]["false_positive_rate"],
        ),
    )

    return best_threshold, best_metrics


def main() -> None:
    """Calibrate the SemanticGuard threshold on validation data."""

    print("\n=== SEMANTIC GUARD THRESHOLD CALIBRATION ===\n")

    reference = load_jsonl(REFERENCE_FILE)
    validation = load_jsonl(VALIDATION_FILE)

    reference_attacks = [
        record
        for record in reference
        if record["label"] == "attack"
    ]

    if not reference_attacks:
        raise ValueError(
            "Reference dataset contains no attack examples."
        )

    print(f"Reference records: {len(reference)}")
    print(f"Reference attacks: {len(reference_attacks)}")
    print(f"Validation records: {len(validation)}")

    attack_texts = [
        record["text"]
        for record in reference_attacks
    ]

    validation_texts = [
        record["text"]
        for record in validation
    ]

    validation_labels = [
        record["label"]
        for record in validation
    ]

    print("\nLoading embedding model...")

    model = SentenceTransformer(MODEL_NAME)

    print("Encoding reference attacks...")

    reference_embeddings = model.encode(
        attack_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    print("Encoding validation prompts...")

    validation_embeddings = model.encode(
        validation_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    print("Calculating similarities...")

    similarity_matrix = cos_sim(
        validation_embeddings,
        reference_embeddings,
    )

    max_similarity_scores = (
        similarity_matrix.max(dim=1).values
        .cpu()
        .tolist()
    )

    print("\n=== SCORE RANGE ===")

    attack_scores = [
        score
        for score, label in zip(
            max_similarity_scores,
            validation_labels,
        )
        if label == "attack"
    ]

    benign_scores = [
        score
        for score, label in zip(
            max_similarity_scores,
            validation_labels,
        )
        if label == "benign"
    ]

    print(
        f"Attack min:  {min(attack_scores):.4f}"
    )
    print(
        f"Attack max:  {max(attack_scores):.4f}"
    )
    print(
        f"Benign min:  {min(benign_scores):.4f}"
    )
    print(
        f"Benign max:  {max(benign_scores):.4f}"
    )

    print("\n=== THRESHOLD EVALUATION ===\n")

    print(
        f"{'Threshold':<12}"
        f"{'Detection':<12}"
        f"{'FPR':<10}"
        f"{'Precision':<12}"
        f"{'Recall':<10}"
        f"{'F1':<10}"
        f"{'Accuracy'}"
    )

    print("-" * 82)

    results: list[
        tuple[float, dict[str, float]]
    ] = []

    for threshold in THRESHOLDS:
        metrics = calculate_metrics(
            max_similarity_scores,
            validation_labels,
            threshold,
        )

        results.append(
            (threshold, metrics)
        )

        print(
            f"{threshold:<12.2f}"
            f"{metrics['detection_rate']:<12.2%}"
            f"{metrics['false_positive_rate']:<10.2%}"
            f"{metrics['precision']:<12.2%}"
            f"{metrics['recall']:<10.2%}"
            f"{metrics['f1']:<10.2%}"
            f"{metrics['accuracy']:.2%}"
        )

    best_threshold, best_metrics = find_best_threshold(
        max_similarity_scores,
        validation_labels,
    )

    print("\n=== BEST THRESHOLD ===\n")

    print(
        f"Selected threshold:     {best_threshold:.2f}"
    )
    print(
        f"Detection rate:          "
        f"{best_metrics['detection_rate']:.2%}"
    )
    print(
        f"False positive rate:     "
        f"{best_metrics['false_positive_rate']:.2%}"
    )
    print(
        f"Precision:               "
        f"{best_metrics['precision']:.2%}"
    )
    print(
        f"Recall:                  "
        f"{best_metrics['recall']:.2%}"
    )
    print(
        f"F1-score:                "
        f"{best_metrics['f1']:.2%}"
    )
    print(
        f"Accuracy:                "
        f"{best_metrics['accuracy']:.2%}"
    )

    print(
        "\nThis threshold was selected using the "
        "VALIDATION set only."
    )
if __name__ == "__main__":
     main()