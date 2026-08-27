import json
from pathlib import Path

from agent.security.rag_context_guard import (
    RAGContextGuard,
)


DATA_DIR = Path(
    "data/security/rag_poisoning/bipia"
)

THRESHOLDS = [
    round(0.20 + i * 0.02, 2)
    for i in range(31)
]


def load_jsonl(path: Path) -> list[dict]:
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


def calculate_metrics(
    predictions: list[bool],
    labels: list[str],
) -> dict[str, float]:

    tp = fp = tn = fn = 0

    for prediction, label in zip(
        predictions,
        labels,
    ):
        actual_poisoned = (
            label == "poisoned"
        )

        if prediction and actual_poisoned:
            tp += 1
        elif prediction and not actual_poisoned:
            fp += 1
        elif not prediction and not actual_poisoned:
            tn += 1
        else:
            fn += 1

    poisoned_total = tp + fn
    clean_total = tn + fp
    total = len(labels)

    detection_rate = (
        tp / poisoned_total
        if poisoned_total
        else 0.0
    )

    false_positive_rate = (
        fp / clean_total
        if clean_total
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = detection_rate

    f1 = (
        2 * precision * recall
        / (precision + recall)
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
    """Calibrate RAGContextGuard on BIPIA-derived data."""

    clean = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    records = clean + poisoned

    print(
        "\n=== RAG CONTEXT GUARD CALIBRATION ===\n"
    )

    print(
        f"Clean records:    {len(clean)}"
    )

    print(
        f"Poisoned records: {len(poisoned)}"
    )

    guard = RAGContextGuard(
        threshold=0.40
    )

    print(
        f"BIPIA attack references: "
        f"{guard.attack_store.size}"
    )

    # ---------------------------------------------------------
    # Cache semantic scores once.
    #
    # The guard is instantiated with threshold 0.40 only
    # so we can reuse its model/store. We collect the
    # underlying maximum similarity score for each record.
    # ---------------------------------------------------------

    scores: list[float] = []
    labels: list[str] = []

    for index, record in enumerate(
        records,
        start=1,
    ):
        context = record["context"]

        # Rule-based matches are always considered
        # certain detections.
        rule_match = guard._check_rules(
            context
        )

        if rule_match is not None:
            score = 1.0

        else:
            segments = guard._split_context(
                context
            )

            segment_embeddings = (
                guard.model.encode(
                    segments,
                    normalize_embeddings=True,
                    convert_to_tensor=True,
                )
            )

            similarity_matrix = (
                guard._similarity_matrix(
                    segment_embeddings
                )
            )

            score = float(
                similarity_matrix.max().item()
            )

        scores.append(score)
        labels.append(
            record["label"]
        )

        if index % 50 == 0:
            print(
                f"Processed: {index}/{len(records)}"
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

    candidates = []

    for threshold in THRESHOLDS:
        predictions = [
            score >= threshold
            for score in scores
        ]

        metrics = calculate_metrics(
            predictions,
            labels,
        )

        candidates.append(
            (
                threshold,
                metrics,
            )
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

    best_threshold, best_metrics = max(
        candidates,
        key=lambda item: (
            item[1]["f1"],
            item[1]["detection_rate"],
            -item[1]["false_positive_rate"],
        ),
    )

    print("\n=== BEST THRESHOLD ===\n")

    print(
        f"Selected threshold:    "
        f"{best_threshold:.2f}"
    )

    print(
        f"Detection rate:         "
        f"{best_metrics['detection_rate']:.2%}"
    )

    print(
        f"False positive rate:    "
        f"{best_metrics['false_positive_rate']:.2%}"
    )

    print(
        f"Precision:              "
        f"{best_metrics['precision']:.2%}"
    )

    print(
        f"Recall:                 "
        f"{best_metrics['recall']:.2%}"
    )

    print(
        f"F1-score:               "
        f"{best_metrics['f1']:.2%}"
    )

    print(
        f"Accuracy:               "
        f"{best_metrics['accuracy']:.2%}"
    )

    print(
        "\nThreshold selected on BIPIA-derived "
        "development data only."
    )


if __name__ == "__main__":
    main()