from sentence_transformers import SentenceTransformer

from agent.security.bipia_attack_store import (
    BIPIAAttackStore,
)


def test_bipia_attack_store_loads_attacks() -> None:
    model = SentenceTransformer(
        "sentence-transformers/all-MiniLM-L6-v2"
    )

    store = BIPIAAttackStore(
        attack_file=(
            "data/external/bipia/raw/"
            "BIPIA-main/benchmark/"
            "text_attack_train.json"
        ),
        model=model,
    )

    assert store.size == 75
    assert store.embeddings is not None