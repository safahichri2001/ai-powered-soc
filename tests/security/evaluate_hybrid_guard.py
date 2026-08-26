import json
import time
from pathlib import Path

from agent.security.input_guard import InputGuard
from agent.security.semantic_guard import SemanticGuard


TEST_FILE = Path(
    "data/security/prepared/test.jsonl"
)

WARMUP_RUNS = 3


def load_jsonl(path: Path) -> list[dict]:
    """Load records from a JSONL file."""

    if not path.exists():
        raise FileNotFoundError(
            f"Test dataset not found: {path}"
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


def calculate_metrics(
    predictions: list[bool],
    labels: list[str],
) -> dict[str, float]:
    """Calculate binary classification metrics."""

    tp = fp = tn = fn = 0

    for predicted_attack, label in zip(
        predictions,
        labels,
    ):
        actual_attack = label == "attack"

        if predicted_attack and actual_attack:
            tp += 1
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and not actual_attack:
            tn += 1
        else:
            fn += 1

    attack_total = tp + fn
    benign_total = tn + fp
    total = len(labels)

    detection_rate = (
        tp / attack_total
        if attack_total
        else 0.0
    )

    false_positive_rate = (
        fp / benign_total
        if benign_total
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


def mean(values: list[float]) -> float:
    """Return the arithmetic mean."""

    return (
        sum(values) / len(values)
        if values
        else 0.0
    )


def percentile(
    values: list[float],
    percentile_value: float,
) -> float:
    """Calculate a simple percentile."""

    if not values:
        return 0.0

    ordered = sorted(values)

    position = (
        percentile_value / 100
    ) * (len(ordered) - 1)

    lower = int(position)
    upper = min(
        lower + 1,
        len(ordered) - 1,
    )

    weight = position - lower

    return (
        ordered[lower]
        + weight
        * (ordered[upper] - ordered[lower])
    )


def summarize_latency(
    values: list[float],
) -> dict[str, float]:
    """Return latency statistics in milliseconds."""

    return {
        "mean_ms": mean(values) * 1000,
        "p50_ms": percentile(values, 50) * 1000,
        "p95_ms": percentile(values, 95) * 1000,
        "min_ms": min(values) * 1000,
        "max_ms": max(values) * 1000,
    }


def print_latency(
    name: str,
    stats: dict[str, float],
) -> None:
    """Print latency statistics."""

    print(f"\n=== {name} LATENCY ===")

    print(
        f"Mean:  {stats['mean_ms']:.2f} ms"
    )
    print(
        f"P50:   {stats['p50_ms']:.2f} ms"
    )
    print(
        f"P95:   {stats['p95_ms']:.2f} ms"
    )
    print(
        f"Min:   {stats['min_ms']:.2f} ms"
    )
    print(
        f"Max:   {stats['max_ms']:.2f} ms"
    )


def main() -> None:
    """Evaluate detection, latency and SemanticGuard invocation rate."""

    records = load_jsonl(TEST_FILE)

    texts = [
        record["text"]
        for record in records
    ]

    labels = [
        record["label"]
        for record in records
    ]

    print("\n=== HYBRID GUARD LATENCY EVALUATION ===\n")
    print(f"Test records: {len(records)}")

    # ---------------------------------------------------------
    # Initialize components once.
    # Model loading is intentionally excluded from latency.
    # ---------------------------------------------------------

    print("\nInitializing guards...")

    input_guard = InputGuard()
    semantic_guard = SemanticGuard()

    # ---------------------------------------------------------
    # Warm-up semantic model.
    # ---------------------------------------------------------

    print(
        f"Running {WARMUP_RUNS} warm-up calls..."
    )

    warmup_text = texts[0]

    for _ in range(WARMUP_RUNS):
        semantic_guard.assess(warmup_text)

    # ---------------------------------------------------------
    # 1. InputGuard only
    # ---------------------------------------------------------

    input_predictions: list[bool] = []
    input_latencies: list[float] = []

    for text in texts:
        start = time.perf_counter()

        result = input_guard.assess(text)

        elapsed = time.perf_counter() - start

        input_latencies.append(elapsed)

        input_predictions.append(
            result.decision == "BLOCK"
        )

    input_metrics = calculate_metrics(
        input_predictions,
        labels,
    )

    # ---------------------------------------------------------
    # 2. SemanticGuard only
    # ---------------------------------------------------------

    semantic_predictions: list[bool] = []
    semantic_latencies: list[float] = []

    for text in texts:
        start = time.perf_counter()

        result = semantic_guard.assess(text)

        elapsed = time.perf_counter() - start

        semantic_latencies.append(elapsed)

        semantic_predictions.append(
            result.decision == "BLOCK"
        )

    semantic_metrics = calculate_metrics(
        semantic_predictions,
        labels,
    )

    # ---------------------------------------------------------
    # 3. Hybrid Guard
    # ---------------------------------------------------------

    hybrid_predictions: list[bool] = []
    hybrid_latencies: list[float] = []
    hybrid_layers: list[str] = []

    semantic_invocations = 0

    for text in texts:
        start = time.perf_counter()

        input_result = input_guard.assess(text)

        if input_result.decision == "BLOCK":
            hybrid_predictions.append(True)
            hybrid_layers.append("input_guard")

            elapsed = time.perf_counter() - start
            hybrid_latencies.append(elapsed)

            continue

        semantic_invocations += 1

        semantic_result = semantic_guard.assess(text)

        if semantic_result.decision == "BLOCK":
            hybrid_predictions.append(True)
            hybrid_layers.append("semantic_guard")
        else:
            hybrid_predictions.append(False)
            hybrid_layers.append("none")

        elapsed = time.perf_counter() - start
        hybrid_latencies.append(elapsed)

    hybrid_metrics = calculate_metrics(
        hybrid_predictions,
        labels,
    )

    # ---------------------------------------------------------
    # Latency statistics
    # ---------------------------------------------------------

    input_latency_stats = summarize_latency(
        input_latencies
    )

    semantic_latency_stats = summarize_latency(
        semantic_latencies
    )

    hybrid_latency_stats = summarize_latency(
        hybrid_latencies
    )

    # ---------------------------------------------------------
    # Invocation statistics
    # ---------------------------------------------------------

    total = len(texts)

    input_blocks = sum(
        prediction
        for prediction in input_predictions
    )

    semantic_blocks = sum(
        prediction
        for prediction in semantic_predictions
    )

    hybrid_blocks = sum(
        prediction
        for prediction in hybrid_predictions
    )

    input_layer_blocks = sum(
        layer == "input_guard"
        for layer in hybrid_layers
    )

    semantic_layer_blocks = sum(
        layer == "semantic_guard"
        for layer in hybrid_layers
    )

    semantic_invocation_rate = (
        semantic_invocations / total
        if total
        else 0.0
    )

    # ---------------------------------------------------------
    # Print metrics
    # ---------------------------------------------------------

    print("\n=== DETECTION RESULTS ===")

    print(
        f"\nInputGuard only:"
    )
    print(
        f"  Detection: {input_metrics['detection_rate']:.2%}"
    )
    print(
        f"  FPR:       {input_metrics['false_positive_rate']:.2%}"
    )
    print(
        f"  F1:        {input_metrics['f1']:.2%}"
    )

    print(
        f"\nSemanticGuard only:"
    )
    print(
        f"  Detection: {semantic_metrics['detection_rate']:.2%}"
    )
    print(
        f"  FPR:       {semantic_metrics['false_positive_rate']:.2%}"
    )
    print(
        f"  F1:        {semantic_metrics['f1']:.2%}"
    )

    print(
        f"\nHybrid Guard:"
    )
    print(
        f"  Detection: {hybrid_metrics['detection_rate']:.2%}"
    )
    print(
        f"  FPR:       {hybrid_metrics['false_positive_rate']:.2%}"
    )
    print(
        f"  F1:        {hybrid_metrics['f1']:.2%}"
    )

    # ---------------------------------------------------------
    # Print latency
    # ---------------------------------------------------------

    print_latency(
        "INPUT GUARD",
        input_latency_stats,
    )

    print_latency(
        "SEMANTIC GUARD",
        semantic_latency_stats,
    )

    print_latency(
        "HYBRID GUARD",
        hybrid_latency_stats,
    )

    # ---------------------------------------------------------
    # Invocation statistics
    # ---------------------------------------------------------

    print("\n=== INVOCATION / BLOCK DISTRIBUTION ===")

    print(
        f"Total prompts:             {total}"
    )

    print(
        f"InputGuard blocked:        "
        f"{input_blocks}"
    )

    print(
        f"SemanticGuard-only blocks: "
        f"{semantic_blocks}"
    )

    print(
        f"Hybrid blocked:            "
        f"{hybrid_blocks}"
    )

    print(
        f"Hybrid by InputGuard:      "
        f"{input_layer_blocks}"
    )

    print(
        f"Hybrid by SemanticGuard:   "
        f"{semantic_layer_blocks}"
    )

    print(
        f"SemanticGuard invocations: "
        f"{semantic_invocations}"
    )

    print(
        f"SemanticGuard invocation rate: "
        f"{semantic_invocation_rate:.2%}"
    )

    # ---------------------------------------------------------
    # Latency overhead
    # ---------------------------------------------------------

    mean_semantic = semantic_latency_stats["mean_ms"]
    mean_hybrid = hybrid_latency_stats["mean_ms"]

    latency_reduction = (
        1 - (mean_hybrid / mean_semantic)
        if mean_semantic
        else 0.0
    )

    print("\n=== HYBRID LATENCY COMPARISON ===")

    print(
        f"SemanticGuard-only mean: "
        f"{mean_semantic:.2f} ms"
    )

    print(
        f"Hybrid mean:             "
        f"{mean_hybrid:.2f} ms"
    )

    print(
        f"Relative reduction:      "
        f"{latency_reduction:.2%}"
    )


if __name__ == "__main__":
    main()