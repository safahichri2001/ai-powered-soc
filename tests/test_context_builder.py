from rag.retrieval.context_builder import build_context


def test_build_context() -> None:
    results = [
        {
            "source": "ssh.md",
            "score": 0.91,
            "content": (
                "SSH authentication events should be investigated "
                "using source IP and user."
            ),
        },
        {
            "source": "wazuh_alerts.md",
            "score": 0.84,
            "content": (
                "Alert severity alone is not sufficient "
                "to determine malicious behavior."
            ),
        },
    ]

    context = build_context(results)

    assert "[Source 1: ssh.md]" in context
    assert "[Source 2: wazuh_alerts.md]" in context
    assert "source IP and user" in context
    assert "Alert severity alone" in context