from __future__ import annotations

from typing import Any, Callable

from agent.integrations.wazuh_client import WazuhIndexerClient, WazuhManagerClient
from agent.tools.base import Tool
from agent.tools.registry import ToolRegistry

"""
SOC operator tools.

WazuhSearchAlerts, WazuhGetAgentInfo, and WazuhIsolateAgent call the
real Wazuh Indexer / Manager APIs (see
agent/integrations/wazuh_client.py). Everything else is still
simulated because it depends on lab infrastructure that doesn't
exist yet (a real firewall/IAM integration) -- see README roadmap.
Swapping a simulated handler for a real one never requires touching
ToolExecutor or ToolMisuseGuard: the enforcement layer only ever
sees the (instruction, tool_name, parameters) triple, never the
handler implementation.

WazuhIsolateAgent's Active Response only knows how to isolate, not
reverse it -- see WazuhManagerClient.trigger_active_response's
docstring. Lifting isolation currently requires direct access to
the target host, not a tool call through this registry.
"""


# ============================================================
# Read-only / low-risk tools -- real Wazuh API calls
# ============================================================

def _make_wazuh_search_alerts(
    indexer: WazuhIndexerClient,
) -> Callable[..., dict[str, Any]]:
    def handler(query: str = "", limit: int = 10) -> dict[str, Any]:
        results = indexer.search_alerts(query=query, limit=limit)
        return {
            "simulated": False,
            "action": "search_alerts",
            "query": query,
            "limit": limit,
            "results": results,
        }

    return handler


def _make_wazuh_get_agent_info(
    manager: WazuhManagerClient,
) -> Callable[..., dict[str, Any]]:
    def handler(agent_id: str) -> dict[str, Any]:
        agent = manager.get_agent(agent_id)
        return {
            "simulated": False,
            "action": "get_agent_info",
            "agent_id": agent_id,
            "agent": agent,
        }

    return handler


def _make_wazuh_isolate_agent(
    manager: WazuhManagerClient,
) -> Callable[..., dict[str, Any]]:
    # Wazuh derives the executable name Active Response invokes from
    # its position among <active-response> blocks in ossec.conf, not
    # necessarily the <name> configured -- "isolate-host0" was
    # confirmed empirically against the lab's actual deployment, not
    # assumed. Redeploying the config elsewhere may change this.
    COMMAND_NAME = "isolate-host0"

    def handler(agent_id: str) -> dict[str, Any]:
        result = manager.trigger_active_response(
            agent_id=agent_id,
            command_name=COMMAND_NAME,
        )
        return {
            "simulated": False,
            "action": "isolate_agent",
            "agent_id": agent_id,
            "api_response": result,
        }

    return handler


def threat_intel_lookup_ip(ip_address: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "lookup_ip",
        "ip_address": ip_address,
        "reputation": "unknown",
    }


# ============================================================
# High-risk / state-changing tools
# ============================================================

def firewall_block_indicator(indicator: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "block_indicator",
        "indicator": indicator,
        "blocked": True,
    }


def firewall_allow_domain(domain: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "allow_domain",
        "domain": domain,
        "allowed": True,
    }


def user_account_disable(username: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "disable_account",
        "username": username,
        "disabled": True,
    }


def user_account_reset_password(username: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "reset_password",
        "username": username,
        "reset": True,
    }


def case_management_close_alert(alert_id: str) -> dict[str, Any]:
    return {
        "simulated": True,
        "action": "close_alert",
        "alert_id": alert_id,
        "closed": True,
    }


# ============================================================
# Registry factory
# ============================================================

def build_default_registry(
    wazuh_manager: WazuhManagerClient | None = None,
    wazuh_indexer: WazuhIndexerClient | None = None,
) -> ToolRegistry:
    """
    Build the registry of tools available to the SOC agent.

    `wazuh_manager` / `wazuh_indexer` default to clients configured
    from environment variables (see .env.example). Constructing
    them never touches the network, so this function is always
    safe to call even when the lab VMs are offline or Wazuh
    credentials are not set -- failures only surface when a Wazuh
    tool is actually invoked, and ToolExecutor turns those into an
    ERROR result rather than a crash.
    """

    manager = wazuh_manager or WazuhManagerClient()
    indexer = wazuh_indexer or WazuhIndexerClient()

    registry = ToolRegistry()

    registry.register(
        Tool(
            name="WazuhSearchAlerts",
            description="Search Wazuh alerts (read-only).",
            handler=_make_wazuh_search_alerts(indexer),
        )
    )

    registry.register(
        Tool(
            name="WazuhGetAgentInfo",
            description="Get information about a monitored agent (read-only).",
            handler=_make_wazuh_get_agent_info(manager),
        )
    )

    registry.register(
        Tool(
            name="ThreatIntelLookupIP",
            description="Look up IP reputation in threat intel (read-only).",
            handler=threat_intel_lookup_ip,
        )
    )

    registry.register(
        Tool(
            name="WazuhIsolateAgent",
            description="Disconnect a monitored host from the network.",
            handler=_make_wazuh_isolate_agent(manager),
        )
    )

    registry.register(
        Tool(
            name="FirewallBlockIndicator",
            description="Add an IP/domain indicator to the firewall block list.",
            handler=firewall_block_indicator,
        )
    )

    registry.register(
        Tool(
            name="FirewallAllowDomain",
            description="Whitelist a domain, bypassing the firewall block list.",
            handler=firewall_allow_domain,
        )
    )

    registry.register(
        Tool(
            name="UserAccountDisable",
            description="Disable a user account.",
            handler=user_account_disable,
        )
    )

    registry.register(
        Tool(
            name="UserAccountResetPassword",
            description="Reset a user account password.",
            handler=user_account_reset_password,
        )
    )

    registry.register(
        Tool(
            name="CaseManagementCloseAlert",
            description="Close/dismiss an alert in the case management system.",
            handler=case_management_close_alert,
        )
    )

    return registry
