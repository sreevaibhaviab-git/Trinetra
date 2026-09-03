"""The explicit allowlist of Blue tools.

Nothing outside this table is callable by a future Trinetra agent. Each entry
carries the metadata Phase 3 needs: what the tool does, which domain it covers,
whether it mutates the range, and how disruptive it is to the business.

`read_only` tools cannot change state. Mutating tools are all routed through the
SafetyGovernor by `app.tools.response`, so an emergency-stopped range refuses
them regardless of what the caller asks for.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from app.tools.investigation import (
    get_active_sessions,
    get_asset_status,
    get_cloud_activity,
    get_cloud_drive_activity,
    get_data_access_activity,
    get_dns_activity,
    get_endpoint_status,
    get_environment_summary,
    get_file_activity,
    get_github_activity,
    get_mailbox_activity,
    get_mailbox_rules,
    get_network_activity,
    get_oauth_activity,
    get_persistence_entries,
    get_process_activity,
    get_recent_logins,
    get_registered_devices,
    get_security_alerts,
    get_timeline,
    get_tokens,
)
from app.tools.response import (
    block_ip,
    block_simulated_connection,
    disable_user,
    isolate_endpoint,
    protect_data_asset,
    remove_mailbox_rule,
    remove_persistence_entry,
    remove_registered_device,
    restrict_asset,
    revoke_token,
    terminate_session,
    terminate_synthetic_process,
)
from app.tools.verification import verify_environment


def _tool(
    fn: Callable[..., Any], description: str, category: str, read_only: bool, impact: str
) -> Dict[str, Any]:
    return {
        "name": fn.__name__,
        "fn": fn,
        "description": description,
        "category": category,
        "read_only": read_only,
        "impact": impact,
    }


BLUE_TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    entry["name"]: entry
    for entry in [
        # -- investigation (read-only) --------------------------------------
        _tool(get_environment_summary, "Overall posture, counts and containment actions so far.",
              "overview", True, "NONE"),
        _tool(get_security_alerts, "Open detections, filterable by severity, source and time.",
              "overview", True, "NONE"),
        _tool(get_timeline, "Unified telemetry across identity, endpoint, SaaS, cloud and data.",
              "overview", True, "NONE"),
        _tool(get_recent_logins, "Sign-in events with source, geography and device trust.",
              "identity", True, "NONE"),
        _tool(get_active_sessions, "Sessions currently live, with device and network context.",
              "identity", True, "NONE"),
        _tool(get_registered_devices, "Devices enrolled against accounts and their compliance.",
              "identity", True, "NONE"),
        _tool(get_oauth_activity, "OAuth grants, live tokens and the authorizations behind them.",
              "identity", True, "NONE"),
        _tool(get_tokens, "Tokens issued against accounts, with scope and status.",
              "identity", True, "NONE"),
        _tool(get_mailbox_activity, "Mailbox reads, searches and rule changes.", "saas", True,
              "NONE"),
        _tool(get_mailbox_rules, "Inbox rules configured on a mailbox.", "saas", True, "NONE"),
        _tool(get_cloud_drive_activity, "Cloud-drive previews, downloads and their sensitivity.",
              "saas", True, "NONE"),
        _tool(get_endpoint_status, "One endpoint's posture, isolation state and inventory sizes.",
              "endpoint", True, "NONE"),
        _tool(get_process_activity, "Processes recorded on an endpoint.", "endpoint", True,
              "NONE"),
        _tool(get_file_activity, "Files and downloads inventoried on an endpoint.", "endpoint",
              True, "NONE"),
        _tool(get_persistence_entries, "Startup and launch items on an endpoint.", "endpoint",
              True, "NONE"),
        _tool(get_dns_activity, "DNS queries seen from an endpoint, with domain category.",
              "network", True, "NONE"),
        _tool(get_network_activity, "Edge flows, endpoint sockets and outbound transfers.",
              "network", True, "NONE"),
        _tool(get_github_activity, "Source-control actions such as clones and pulls.", "cloud",
              True, "NONE"),
        _tool(get_cloud_activity, "Cloud control-plane actions and their outcomes.", "cloud",
              True, "NONE"),
        _tool(get_asset_status, "One asset's criticality, exposure and event counts.", "cloud",
              True, "NONE"),
        _tool(get_data_access_activity, "Reads, staging writes and egress against data stores.",
              "data", True, "NONE"),
        _tool(verify_environment, "Re-derive containment, risk by domain and remaining threats.",
              "verification", True, "NONE"),
        # -- response (mutating) --------------------------------------------
        _tool(revoke_token, "Revoke an OAuth or personal access token.", "identity", False,
              "LOW"),
        _tool(terminate_session, "End one authenticated session.", "identity", False, "LOW"),
        _tool(remove_mailbox_rule, "Delete an inbox rule from a mailbox.", "saas", False, "LOW"),
        _tool(terminate_synthetic_process, "Stop a process recorded on an endpoint.", "endpoint",
              False, "LOW"),
        _tool(remove_persistence_entry, "Remove a startup or launch item from an endpoint.",
              "endpoint", False, "LOW"),
        _tool(block_simulated_connection, "Block one socket at the host firewall.", "network",
              False, "LOW"),
        _tool(block_ip, "Block a source address at the network edge.", "network", False, "LOW"),
        _tool(remove_registered_device, "Unenrol a device and drop sessions bound to it.",
              "identity", False, "MEDIUM"),
        _tool(disable_user, "Disable an account pending credential reset.", "identity", False,
              "MEDIUM"),
        _tool(isolate_endpoint, "Quarantine an endpoint from the network.", "endpoint", False,
              "MEDIUM"),
        _tool(restrict_asset, "Place an asset under restricted access.", "cloud", False, "HIGH"),
        _tool(protect_data_asset, "Apply an emergency access policy to a data store.", "data",
              False, "HIGH"),
    ]
}


def blue_tool_names() -> list:
    """Every tool name a Trinetra agent is allowed to call."""
    return sorted(BLUE_TOOL_REGISTRY)


def call_blue_tool(env, name: str, **kwargs) -> Any:
    """Invoke an allowlisted Blue tool. Anything else is refused."""
    entry = BLUE_TOOL_REGISTRY.get(name)
    if entry is None:
        return {"success": False, "error": "TOOL_NOT_ALLOWED", "target": name}
    return entry["fn"](env, **kwargs)
