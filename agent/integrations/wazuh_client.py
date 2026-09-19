from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable

import requests
import urllib3
from dotenv import load_dotenv

# Loads variables from a local .env into os.environ (never overrides
# variables already set in the real environment). No-op if .env
# does not exist, so this is safe to run unconditionally at import.
load_dotenv()


class WazuhClientError(RuntimeError):
    """Raised when a Wazuh API call cannot be completed."""


def _with_connection_retry(
    send: Callable[[], requests.Response],
    max_retries: int = 2,
    backoff_seconds: float = 1.0,
) -> requests.Response:
    """
    Retry a request on transient connection failures (a reset/
    aborted keep-alive connection, observed repeatedly against the
    lab's Indexer -- always succeeding on the very next attempt),
    but never on an HTTP error response, which is a real failure
    worth surfacing immediately rather than retrying.
    """

    last_exc: requests.exceptions.ConnectionError | None = None

    for attempt in range(max_retries + 1):
        try:
            return send()

        except requests.exceptions.ConnectionError as exc:
            last_exc = exc

            if attempt < max_retries:
                time.sleep(backoff_seconds * (attempt + 1))

    assert last_exc is not None
    raise last_exc


@dataclass(frozen=True)
class WazuhConfig:
    """Connection settings for one Wazuh service (Manager or Indexer)."""

    base_url: str
    username: str
    password: str
    verify_ssl: bool = False

    @classmethod
    def from_env(cls, prefix: str) -> "WazuhConfig":
        return cls(
            base_url=os.environ.get(f"{prefix}_URL", "").rstrip("/"),
            username=os.environ.get(f"{prefix}_USERNAME", ""),
            password=os.environ.get(f"{prefix}_PASSWORD", ""),
            verify_ssl=(
                os.environ.get(f"{prefix}_VERIFY_SSL", "false").lower()
                == "true"
            ),
        )

    def require_configured(self, service_name: str) -> None:
        if not self.base_url or not self.username or not self.password:
            raise WazuhClientError(
                f"{service_name} is not configured "
                f"(base URL, username and password are all required)."
            )


class WazuhManagerClient:
    """
    Thin client for the Wazuh Manager REST API (default port 55000).

    Authenticates lazily and caches the JWT token -- constructing
    this client never makes a network call, only the first actual
    request does. This keeps it safe to construct unconditionally
    (e.g. as part of building a tool registry) even when the lab
    VMs are offline or credentials are not yet configured.
    """

    TOKEN_TTL_SECONDS = 850  # Wazuh default token lifetime is 900s.

    def __init__(self, config: WazuhConfig | None = None) -> None:
        self.config = config or WazuhConfig.from_env(prefix="WAZUH_API")
        self._session = requests.Session()
        self._token: str | None = None
        self._token_expiry: float = 0.0

        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _authenticate(self) -> str:
        self.config.require_configured("Wazuh Manager API")

        try:
            response = _with_connection_retry(
                lambda: self._session.post(
                    f"{self.config.base_url}/security/user/authenticate",
                    auth=(self.config.username, self.config.password),
                    verify=self.config.verify_ssl,
                    timeout=10,
                )
            )
            response.raise_for_status()

        except requests.RequestException as exc:
            raise WazuhClientError(
                f"Unable to authenticate to Wazuh Manager at "
                f"{self.config.base_url}: {exc}"
            ) from exc

        token = response.json().get("data", {}).get("token")

        if not token:
            raise WazuhClientError(
                "Wazuh Manager authentication response did not "
                "contain a token."
            )

        self._token = token
        self._token_expiry = time.time() + self.TOKEN_TTL_SECONDS
        return token

    def _get_token(self) -> str:
        if self._token is None or time.time() >= self._token_expiry:
            return self._authenticate()
        return self._token

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        token = self._get_token()

        def send(auth_token: str) -> requests.Response:
            return self._session.request(
                method,
                f"{self.config.base_url}{path}",
                headers={"Authorization": f"Bearer {auth_token}"},
                verify=self.config.verify_ssl,
                timeout=10,
                **kwargs,
            )

        try:
            response = _with_connection_retry(lambda: send(token))

            if response.status_code == 401:
                # Token expired/invalidated server-side -- refresh once.
                token = self._authenticate()
                response = _with_connection_retry(lambda: send(token))

            response.raise_for_status()

        except requests.RequestException as exc:
            raise WazuhClientError(
                f"Wazuh Manager request failed ({method} {path}): {exc}"
            ) from exc

        return response.json()

    def list_agents(self, limit: int = 50) -> list[dict[str, Any]]:
        payload = self._request(
            "GET", "/agents", params={"limit": limit}
        )
        return payload.get("data", {}).get("affected_items", [])

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        payload = self._request(
            "GET", "/agents", params={"agents_list": agent_id}
        )
        items = payload.get("data", {}).get("affected_items", [])

        if not items:
            raise WazuhClientError(
                f"No agent found with id '{agent_id}'."
            )

        return items[0]

    def trigger_active_response(
        self,
        agent_id: str,
        command_name: str,
        arguments: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Trigger an Active Response command on a specific agent.

        `command_name` must match the executable name the agent
        actually has under active-response/bin/ -- Wazuh derives
        this from the command's position among configured
        <active-response> blocks (e.g. "isolate-host0"), not
        necessarily the <name> given in ossec.conf's <command>
        block. Verify empirically (this was confirmed the hard way:
        the API call succeeds regardless of whether the name is
        right, and silently does nothing if it's wrong).

        Known limitation: there is no simple "cancel on demand" via
        this API for a manually-triggered command with no configured
        <timeout> -- reversing an action triggered this way currently
        requires direct access to the target host (see
        active-response/bin/<command_name> and send it a `{"command":
        "delete"}` line directly), not something this method can do.
        """

        return self._request(
            "PUT",
            "/active-response",
            params={"agents_list": agent_id},
            json={
                "command": f"!{command_name}",
                "arguments": arguments or [],
            },
        )


class WazuhIndexerClient:
    """
    Thin client for the Wazuh Indexer (OpenSearch) alert store,
    default port 9200. Uses HTTP basic auth, separate from the
    Manager API's JWT auth and typically separate credentials.
    """

    def __init__(self, config: WazuhConfig | None = None) -> None:
        self.config = config or WazuhConfig.from_env(prefix="WAZUH_INDEXER")
        self._session = requests.Session()

        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def search_alerts(
        self,
        query: str = "",
        limit: int = 10,
        index_pattern: str = "wazuh-alerts-*",
        since: str | None = None,
        ascending: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Search alerts. `since` (an ISO8601 timestamp) restricts
        results to alerts strictly after it, for watermark-based
        polling -- pass `ascending=True` alongside it so results
        come back oldest-first and a caller can safely advance its
        watermark to the last item returned.

        Known limitation: filtering is a plain `timestamp > since`
        range, not a compound (timestamp, id) cursor, so two alerts
        sharing the exact same timestamp at a page boundary could
        in principle be split across polls. Not addressed here.
        """

        self.config.require_configured("Wazuh Indexer")

        filters: list[dict[str, Any]] = []

        if query:
            filters.append({"query_string": {"query": query}})

        if since:
            filters.append({"range": {"timestamp": {"gt": since}}})

        if not filters:
            search_query: dict[str, Any] = {"match_all": {}}
        elif len(filters) == 1:
            search_query = filters[0]
        else:
            search_query = {"bool": {"must": filters}}

        body: dict[str, Any] = {
            "size": limit,
            "query": search_query,
            "sort": [
                {"timestamp": {"order": "asc" if ascending else "desc"}}
            ],
        }

        try:
            response = _with_connection_retry(
                lambda: self._session.post(
                    f"{self.config.base_url}/{index_pattern}/_search",
                    json=body,
                    auth=(self.config.username, self.config.password),
                    verify=self.config.verify_ssl,
                    timeout=10,
                )
            )
            response.raise_for_status()

        except requests.RequestException as exc:
            raise WazuhClientError(
                f"Wazuh Indexer search failed at "
                f"{self.config.base_url}: {exc}"
            ) from exc

        hits = response.json().get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]
