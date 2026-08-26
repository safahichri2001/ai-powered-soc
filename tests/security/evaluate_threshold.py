import json
from pathlib import Path

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim


SECURITY_DIR = Path("data/security")
PREPARED_DIR = SECURITY_DIR / "prepared"

REFERENCE_FILE = PREPARED_DIR / "reference.jsonl"
TEST_FILE = PREPARED_DIR / "test.jsonl"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# FROZEN threshold selected on the validation set.
THRESHOLD = 0.40


def load_jsonl(path: Path) -> list[dict]:
    """Load records from a JSONL file."""

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
                    f"Invalid JSON in {path}:{line_number}"
                ) from exc

    return records


def calculate_metrics(
    scores: list[float],
    labels: list[str],
    threshold: float,
) -> dict[str, float]:
    """Calculate binary classification metrics."""

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
    total = len(labels)

    detection_rate = (
        tp / total_attacks
        if total_attacks
        else 0.0
    )

    false_positive_rate = (
        fp / total_benign
        if total_benign
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = detection_rate

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    accuracy = (
        (tp + tn) / total
        if total
        else 0.0
    )

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def main() -> None:
    """Evaluate the frozen threshold on the unseen test set."""

    print("\n=== SEMANTIC GUARD FINAL TEST ===\n")

    reference = load_jsonl(REFERENCE_FILE)
    test = load_jsonl(TEST_FILE)

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
    print(f"Test records:      {len(test)}")
    print(f"Frozen threshold:  {THRESHOLD:.2f}")

    model = SentenceTransformer(MODEL_NAME)

    attack_texts = [
        record["text"]
        for record in reference_attacks
    ]

    test_texts = [
        record["text"]
        for record in test
    ]

    test_labels = [
        record["label"]
        for record in test
    ]

    print("\nEncoding reference attacks...")

    reference_embeddings = model.encode(
        attack_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    print("Encoding test prompts...")

    test_embeddings = model.encode(
        test_texts,
        normalize_embeddings=True,
        convert_to_tensor=True,
        show_progress_bar=True,
    )

    print("Calculating similarities...")

    similarity_matrix = cos_sim(
        test_embeddings,
        reference_embeddings,
    )

    max_scores = (
        similarity_matrix.max(dim=1)
        .values
        .cpu()
        .tolist()
    )

    metrics = calculate_metrics(
        max_scores,
        test_labels,
        THRESHOLD,
    )

    attack_scores = [
        score
        for score, label in zip(
            max_scores,
            test_labels,
        )
        if label == "attack"
    ]

    benign_scores = [
        score
        for score, label in zip(
            max_scores,
            test_labels,
        )
        if label == "benign"
    ]

    print("\n=== TEST SCORE RANGE ===")
    print(f"Attack min:  {min(attack_scores):.4f}")
    print(f"Attack max:  {max(attack_scores):.4f}")
    print(f"Benign min:  {min(benign_scores):.4f}")
    print(f"Benign max:  {max(benign_scores):.4f}")

    print("\n=== FINAL TEST RESULTS ===")
    print(
        f"Detection rate:      "
        f"{metrics['detection_rate']:.2%}"
    )
    print(
        f"False positive rate:  "
        f"{metrics['false_positive_rate']:.2%}"
    )
    print(
        f"Precision:            "
        f"{metrics['precision']:.2%}"
    )
    print(
        f"Recall:               "
        f"{metrics['recall']:.2%}"
    )
    print(
        f"F1-score:             "
        f"{metrics['f1']:.2%}"
    )
    print(
        f"Accuracy:             "
        f"{metrics['accuracy']:.2%}"
    )

    print(
        "\nThreshold 0.40 was selected on the VALIDATION set "
        "and was not tuned using the TEST set."
    )


if __name__ == "__main__":
    main()