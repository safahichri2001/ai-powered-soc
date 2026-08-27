import json
from pathlib import Path

from rag.embeddings.embedder import EmbeddingModel
from rag.ingestion.chunker import DocumentChunk
from rag.retrieval.retriever import Retriever
from rag.retrieval.vector_store import LocalVectorStore


DATA_DIR = Path(
    "data/security/rag_poisoning/bipia"
)


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL records."""

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
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


def build_chunks(
    records: list[dict],
) -> list[DocumentChunk]:
    """Convert BIPIA contexts into RAG chunks."""

    chunks: list[DocumentChunk] = []

    for record in records:
        chunks.append(
            DocumentChunk(
                chunk_id=record["id"],
                source=(
                    f"BIPIA:"
                    f"{record['scenario']}:"
                    f"{record['id']}"
                ),
                content=record["context"],
            )
        )

    return chunks


def build_store(
    chunks: list[DocumentChunk],
    collection_name: str,
    path: str,
) -> LocalVectorStore:
    """Build a local Qdrant collection."""

    embedder = EmbeddingModel(
        device="cpu",
    )

    embeddings = embedder.encode_chunks(
        chunks
    )

    store = LocalVectorStore(
        path=path,
        collection_name=collection_name,
    )

    store.upsert(
        chunks,
        embeddings,
    )

    return store


def main() -> None:
    """Run the BIPIA retrieval baseline."""

    clean_records = load_jsonl(
        DATA_DIR / "clean.jsonl"
    )

    poisoned_records = load_jsonl(
        DATA_DIR / "poisoned.jsonl"
    )

    print(
        "\n=== BIPIA RAG POISONING BASELINE ===\n"
    )

    print(
        f"Clean records:    {len(clean_records)}"
    )

    print(
        f"Poisoned records: {len(poisoned_records)}"
    )

    # ---------------------------------------------------------
    # Build poisoned corpus
    # ---------------------------------------------------------

    poisoned_chunks = build_chunks(
        poisoned_records
    )

    poisoned_store = build_store(
        poisoned_chunks,
        collection_name="bipia_poisoned_baseline",
        path="test_bipia_poisoned_baseline",
    )

    retriever = Retriever(
        vector_store=poisoned_store,
    )

    # ---------------------------------------------------------
    # Evaluate using the task associated with each context
    # ---------------------------------------------------------

    total_queries = 0
    poisoned_contexts_retrieved = 0

    scenario_results: dict[str, list[int]] = {
        "email": [0, 0],
        "code": [0, 0],
    }

    position_results: dict[str, list[int]] = {
        "start": [0, 0],
        "middle": [0, 0],
        "end": [0, 0],
    }

    family_results: dict[str, list[int]] = {}

    for index, record in enumerate(
        poisoned_records,
        start=1,
    ):
        task = str(
            record.get("task", "")
        ).strip()

        if not task:
            continue

        total_queries += 1

        results = retriever.search(
            task,
            top_k=5,
        )

        retrieved_ids = {
            result["chunk_id"]
            for result in results
        }

        target_retrieved = (
            record["id"] in retrieved_ids
        )

        if target_retrieved:
            poisoned_contexts_retrieved += 1

        scenario = record[
            "scenario"
        ]

        scenario_results[
            scenario
        ][0] += 1

        if target_retrieved:
            scenario_results[
                scenario
            ][1] += 1

        position = record[
            "position"
        ]

        position_results[
            position
        ][0] += 1

        if target_retrieved:
            position_results[
                position
            ][1] += 1

        family = record[
            "attack_family"
        ]

        if family not in family_results:
            family_results[family] = [0, 0]

        family_results[
            family
        ][0] += 1

        if target_retrieved:
            family_results[
                family
            ][1] += 1

        if index <= 5:
            print(
                f"\nExample {index}"
            )
            print(
                f"Scenario: {scenario}"
            )
            print(
                f"Attack family: "
                f"{family}"
            )
            print(
                f"Position: {position}"
            )
            print(
                f"Target retrieved: "
                f"{target_retrieved}"
            )

    retrieval_rate = (
        poisoned_contexts_retrieved
        / total_queries
        if total_queries
        else 0.0
    )

    print(
        "\n=== OVERALL BASELINE ==="
    )

    print(
        f"Queries evaluated:       "
        f"{total_queries}"
    )

    print(
        f"Poisoned contexts retrieved: "
        f"{poisoned_contexts_retrieved}"
    )

    print(
        f"Target retrieval rate:    "
        f"{retrieval_rate:.2%}"
    )

    print(
        "\n=== BY SCENARIO ==="
    )

    for scenario, (
        total,
        retrieved,
    ) in sorted(
        scenario_results.items()
    ):
        rate = (
            retrieved / total
            if total
            else 0.0
        )

        print(
            f"{scenario:<10}"
            f" {retrieved:>3}/{total:<3}"
            f" ({rate:.2%})"
        )

    print(
        "\n=== BY INSERTION POSITION ==="
    )

    for position, (
        total,
        retrieved,
    ) in sorted(
        position_results.items()
    ):
        rate = (
            retrieved / total
            if total
            else 0.0
        )

        print(
            f"{position:<10}"
            f" {retrieved:>3}/{total:<3}"
            f" ({rate:.2%})"
        )

    print(
        "\n=== BY ATTACK FAMILY ==="
    )

    for family, (
        total,
        retrieved,
    ) in sorted(
        family_results.items()
    ):
        rate = (
            retrieved / total
            if total
            else 0.0
        )

        print(
            f"{family:<35}"
            f" {retrieved:>3}/{total:<3}"
            f" ({rate:.2%})"
        )

    print(
        "\n=== DONE ==="
    )


if __name__ == "__main__":
    main()