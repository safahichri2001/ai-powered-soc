from pathlib import Path

from rag.ingestion.loader import load_documents


def test_load_documents() -> None:
    knowledge_dir = Path("rag/knowledge/documents")

    documents = load_documents(knowledge_dir)

    assert len(documents) == 3

    sources = {document.source for document in documents}

    assert "ssh.md" in sources
    assert "sudo.md" in sources
    assert "wazuh_alerts.md" in sources