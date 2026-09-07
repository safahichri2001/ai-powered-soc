from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.integrations.wazuh_client import (
    WazuhClientError,
    WazuhConfig,
    WazuhIndexerClient,
    WazuhManagerClient,
)


def _response(json_data: dict, status_code: int = 200) -> MagicMock:
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.json.return_value = json_data

    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"status {status_code}"
        )
    else:
        response.raise_for_status.return_value = None

    return response


# ============================================================
# WazuhConfig
# ============================================================


def test_config_from_env_reads_prefixed_variables(monkeypatch):
    monkeypatch.setenv("WAZUH_API_URL", "https://10.0.0.10:55000")
    monkeypatch.setenv("WAZUH_API_USERNAME", "wazuh-wui")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "secret")
    monkeypatch.setenv("WAZUH_API_VERIFY_SSL", "true")

    config = WazuhConfig.from_env(prefix="WAZUH_API")

    assert config.base_url == "https://10.0.0.10:55000"
    assert config.username == "wazuh-wui"
    assert config.password == "secret"
    assert config.verify_ssl is True


def test_config_from_env_defaults_are_empty(monkeypatch):
    for var in (
        "WAZUH_API_URL",
        "WAZUH_API_USERNAME",
        "WAZUH_API_PASSWORD",
        "WAZUH_API_VERIFY_SSL",
    ):
        monkeypatch.delenv(var, raising=False)

    config = WazuhConfig.from_env(prefix="WAZUH_API")

    assert config == WazuhConfig(
        base_url="", username="", password="", verify_ssl=False
    )


# ============================================================
# Constructing a client never touches the network
# ============================================================


def test_manager_client_construction_makes_no_request():
    with patch.object(requests.Session, "post") as mock_post:
        WazuhManagerClient(
            config=WazuhConfig("", "", "", False)
        )
        mock_post.assert_not_called()


def test_indexer_client_construction_makes_no_request():
    with patch.object(requests.Session, "post") as mock_post:
        WazuhIndexerClient(
            config=WazuhConfig("", "", "", False)
        )
        mock_post.assert_not_called()


# ============================================================
# WazuhManagerClient
# ============================================================


def test_unconfigured_manager_client_raises_clear_error():
    client = WazuhManagerClient(config=WazuhConfig("", "", "", False))

    with pytest.raises(WazuhClientError, match="not configured"):
        client.get_agent("001")


def test_get_agent_authenticates_then_fetches_agent():
    config = WazuhConfig("https://10.0.0.10:55000", "user", "pass", False)
    client = WazuhManagerClient(config=config)

    auth_response = _response({"data": {"token": "jwt-token"}})
    agents_response = _response(
        {
            "data": {
                "affected_items": [
                    {"id": "001", "name": "kali", "status": "active"}
                ]
            }
        }
    )

    with patch.object(
        requests.Session, "post", return_value=auth_response
    ) as mock_post, patch.object(
        requests.Session, "request", return_value=agents_response
    ) as mock_request:

        agent = client.get_agent("001")

    assert agent["name"] == "kali"
    mock_post.assert_called_once()
    mock_request.assert_called_once()

    _, kwargs = mock_request.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer jwt-token"


def test_token_is_reused_across_calls_within_ttl():
    config = WazuhConfig("https://10.0.0.10:55000", "user", "pass", False)
    client = WazuhManagerClient(config=config)

    auth_response = _response({"data": {"token": "jwt-token"}})
    agents_response = _response(
        {"data": {"affected_items": [{"id": "001"}]}}
    )

    with patch.object(
        requests.Session, "post", return_value=auth_response
    ) as mock_post, patch.object(
        requests.Session, "request", return_value=agents_response
    ):

        client.get_agent("001")
        client.get_agent("001")

    assert mock_post.call_count == 1


def test_get_agent_raises_when_agent_not_found():
    config = WazuhConfig("https://10.0.0.10:55000", "user", "pass", False)
    client = WazuhManagerClient(config=config)

    auth_response = _response({"data": {"token": "jwt-token"}})
    empty_response = _response({"data": {"affected_items": []}})

    with patch.object(requests.Session, "post", return_value=auth_response), \
         patch.object(requests.Session, "request", return_value=empty_response):

        with pytest.raises(WazuhClientError, match="No agent found"):
            client.get_agent("999")


def test_connection_failure_raises_wazuh_client_error():
    config = WazuhConfig("https://10.0.0.10:55000", "user", "pass", False)
    client = WazuhManagerClient(config=config)

    with patch.object(
        requests.Session,
        "post",
        side_effect=requests.ConnectionError("no route to host"),
    ):
        with pytest.raises(WazuhClientError, match="Unable to authenticate"):
            client.get_agent("001")


# ============================================================
# WazuhIndexerClient
# ============================================================


def test_unconfigured_indexer_client_raises_clear_error():
    client = WazuhIndexerClient(config=WazuhConfig("", "", "", False))

    with pytest.raises(WazuhClientError, match="not configured"):
        client.search_alerts()


def test_search_alerts_parses_hits_and_uses_basic_auth():
    config = WazuhConfig("https://10.0.0.10:9200", "admin", "admin", False)
    client = WazuhIndexerClient(config=config)

    search_response = _response(
        {
            "hits": {
                "hits": [
                    {"_source": {"rule": {"description": "SSH brute force"}}},
                    {"_source": {"rule": {"description": "Port scan"}}},
                ]
            }
        }
    )

    with patch.object(
        requests.Session, "post", return_value=search_response
    ) as mock_post:
        results = client.search_alerts(query="agent.ip:45.33.12.9", limit=5)

    assert len(results) == 2
    assert results[0]["rule"]["description"] == "SSH brute force"

    _, kwargs = mock_post.call_args
    assert kwargs["auth"] == ("admin", "admin")
    assert kwargs["json"]["size"] == 5
    assert kwargs["json"]["query"] == {
        "query_string": {"query": "agent.ip:45.33.12.9"}
    }


def test_search_alerts_with_no_query_uses_match_all():
    config = WazuhConfig("https://10.0.0.10:9200", "admin", "admin", False)
    client = WazuhIndexerClient(config=config)

    search_response = _response({"hits": {"hits": []}})

    with patch.object(
        requests.Session, "post", return_value=search_response
    ) as mock_post:
        client.search_alerts()

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["query"] == {"match_all": {}}
