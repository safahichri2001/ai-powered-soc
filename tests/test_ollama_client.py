from agent.llm.ollama_client import OllamaClient


def test_ollama_client() -> None:
    client = OllamaClient()

    response = client.generate(
        "Answer in one sentence: What is SSH?"
    )

    assert response.strip()