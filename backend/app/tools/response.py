"""Simulated defensive actions. Each one mutates the live environment state."""

from __future__ import annotations

from typing import Any, Dict

from app.models.environment import (
    BlockedIP,
    EventOutcome,
    MailboxEvent,
    SessionStatus,
    SimulationStatus,
    TokenStatus,
)
from app.simulator.environment import CyberEnvironment

# Fault flag consumed by revoke_token; deterministic, never random.
IAM_FAULT = "iam_service_unavailable"
IAM_FAULT_TOKEN = "oauth-8492"

# How disruptive each action is to the business, for a future agent that should
# prefer the least-disruptive containment that still closes the path.
ACTION_IMPACT: Dict[str, str] = {
    "revoke_token": "LOW",
    "terminate_session": "LOW",
    "remove_mailbox_rule": "LOW",
    "terminate_synthetic_process": "LOW",
    "remove_persistence_entry": "LOW",
    "block_simulated_connection": "LOW",
    "block_ip": "LOW",
    "remove_registered_device": "MEDIUM",
    "disable_user": "MEDIUM",
    "isolate_endpoint": "MEDIUM",
    "restrict_asset": "HIGH",
    "protect_data_asset": "HIGH",
}


def _ok(action: str, target: str, message: str) -> Dict[str, Any]:
    return {
        "success": True,
        "action": action,
        "target": target,
        "message": message,
        "state_changed": True,
        "impact": ACTION_IMPACT.get(action, "MEDIUM"),
    }


def _fail(action: str, target: str, error: str) -> Dict[str, Any]:
    return {
        "success": False,
        "action": action,
        "target": target,
        "error": error,
        "message": f"{action} failed: {error}",
        "state_changed": False,
        "impact": ACTION_IMPACT.get(action, "MEDIUM"),
    }


def _halted(env: CyberEnvironment, action: str, target: str) -> Dict[str, Any]:
    """Refuse a mutation the SafetyGovernor has locked out. No tool bypasses it."""
    safety = env.state.safety
    if safety.mutations_locked or safety.simulation_status is SimulationStatus.EMERGENCY_STOPPED:
        return _fail(action, target, "SIMULATION_EMERGENCY_STOPPED")
    return {}


def _record(env: CyberEnvironment, action: str, target: str) -> None:
    env.state.incident_status.containment_actions.append(f"{action}:{target}")


def revoke_token(env: CyberEnvironment, token_id: str) -> Dict[str, Any]:
    halted = _halted(env, "revoke_token", token_id)
    if halted:
        return halted

    if env.faults.get(IAM_FAULT) and token_id == IAM_FAULT_TOKEN:
        return _fail("revoke_token", token_id, "IAM_SERVICE_UNAVAILABLE")

    token = env.state.tokens.get(token_id)
    if token is None:
        return _fail("revoke_token", token_id, "TOKEN_NOT_FOUND")
    if token.status is not TokenStatus.ACTIVE:
        return _fail("revoke_token", token_id, "TOKEN_ALREADY_REVOKED")

    token.status = TokenStatus.REVOKED
    _record(env, "revoke_token", token_id)
    return _ok("revoke_token", token_id, "Token revoked")


def disable_user(env: CyberEnvironment, user_id: str) -> Dict[str, Any]:
    halted = _halted(env, "disable_user", user_id)
    if halted:
        return halted

    user = env.state.users.get(user_id)
    if user is None:
        return _fail("disable_user", user_id, "USER_NOT_FOUND")
    if user.status == "disabled":
        return _fail("disable_user", user_id, "USER_ALREADY_DISABLED")

    user.status = "disabled"
    _record(env, "disable_user", user_id)
    return _ok("disable_user", user_id, "Account disabled pending credential reset")


def terminate_session(env: CyberEnvironment, session_id: str) -> Dict[str, Any]:
    halted = _halted(env, "terminate_session", session_id)
    if halted:
        return halted

    session = env.state.sessions.get(session_id)
    if session is None:
        return _fail("terminate_session", session_id, "SESSION_NOT_FOUND")
    if session.status is not SessionStatus.ACTIVE:
        return _fail("terminate_session", session_id, "SESSION_NOT_ACTIVE")

    session.status = SessionStatus.TERMINATED
    _record(env, "terminate_session", session_id)
    return _ok("terminate_session", session_id, "Session terminated")


def block_ip(env: CyberEnvironment, ip_address: str) -> Dict[str, Any]:
    halted = _halted(env, "block_ip", ip_address)
    if halted:
        return halted

    if any(b.ip_address == ip_address for b in env.state.blocked_ips):
        return _fail("block_ip", ip_address, "IP_ALREADY_BLOCKED")

    env.state.blocked_ips.append(
        BlockedIP(
            ip_address=ip_address,
            reason="Containment action issued by Trinetra",
            blocked_at=env.state.simulation_time,
            blocked_by="trinetra-agent",
            scope="global",
        )
    )
    _record(env, "block_ip", ip_address)
    return _ok("block_ip", ip_address, "Source address blocked at the edge")


def restrict_asset(env: CyberEnvironment, asset_id: str) -> Dict[str, Any]:
    halted = _halted(env, "restrict_asset", asset_id)
    if halted:
        return halted

    asset = env.state.assets.get(asset_id)
    if asset is None:
        return _fail("restrict_asset", asset_id, "ASSET_NOT_FOUND")
    if asset.status == "restricted":
        return _fail("restrict_asset", asset_id, "ASSET_ALREADY_RESTRICTED")

    asset.status = "restricted"
    asset.restricted = True
    _record(env, "restrict_asset", asset_id)
    return _ok("restrict_asset", asset_id, "Asset placed under restricted access")


def remove_registered_device(env: CyberEnvironment, device_id: str) -> Dict[str, Any]:
    """Unenrol a device. Sessions riding that device stop working with it."""
    halted = _halted(env, "remove_registered_device", device_id)
    if halted:
        return halted

    device = env.state.devices.pop(device_id, None)
    if device is None:
        return _fail("remove_registered_device", device_id, "DEVICE_NOT_FOUND")

    user = env.state.users.get(device.owner)
    if user and device_id in user.known_devices:
        user.known_devices.remove(device_id)
    dropped = [
        s
        for s in env.state.sessions.values()
        if s.device_id == device_id and s.status is SessionStatus.ACTIVE
    ]
    for session in dropped:
        session.status = SessionStatus.TERMINATED
    _record(env, "remove_registered_device", device_id)
    return _ok(
        "remove_registered_device",
        device_id,
        f"Device unenrolled; {len(dropped)} bound session(s) terminated",
    )


def remove_mailbox_rule(env: CyberEnvironment, rule_id: str) -> Dict[str, Any]:
    halted = _halted(env, "remove_mailbox_rule", rule_id)
    if halted:
        return halted

    rule = next((r for r in env.state.mailbox_rules if r.rule_id == rule_id), None)
    if rule is None:
        return _fail("remove_mailbox_rule", rule_id, "RULE_NOT_FOUND")

    env.state.mailbox_rules.remove(rule)
    env.state.mailbox_events.append(
        MailboxEvent(
            event_id=f"mail-rm-{rule_id}",
            timestamp=env.state.simulation_time,
            mailbox=rule.mailbox,
            event_type="inbox_rule_removed",
            subject=f"rule removed: {rule.name}",
            sender="",
            recipient=rule.mailbox,
            outcome=EventOutcome.SUCCESS,
            details={"rule_id": rule_id, "removed_by": "trinetra-agent"},
        )
    )
    _record(env, "remove_mailbox_rule", rule_id)
    return _ok("remove_mailbox_rule", rule_id, "Inbox rule removed and mailbox state restored")


def isolate_endpoint(env: CyberEnvironment, endpoint_id: str) -> Dict[str, Any]:
    """Cut the endpoint off the network. Its outbound activity stops leaving."""
    halted = _halted(env, "isolate_endpoint", endpoint_id)
    if halted:
        return halted

    endpoint = env.state.endpoints.get(endpoint_id)
    if endpoint is None:
        return _fail("isolate_endpoint", endpoint_id, "ENDPOINT_NOT_FOUND")
    if endpoint.isolated:
        return _fail("isolate_endpoint", endpoint_id, "ENDPOINT_ALREADY_ISOLATED")

    endpoint.isolated = True
    endpoint.status = "isolated"
    for connection in endpoint.network_connections:
        connection.state = "blocked"
    _record(env, "isolate_endpoint", endpoint_id)
    return _ok("isolate_endpoint", endpoint_id, "Endpoint isolated from the network")


def terminate_synthetic_process(
    env: CyberEnvironment, endpoint_id: str, process_id: int
) -> Dict[str, Any]:
    """Stop a process in the simulation. No OS process is ever touched."""
    target = f"{endpoint_id}:{process_id}"
    halted = _halted(env, "terminate_synthetic_process", target)
    if halted:
        return halted

    endpoint = env.state.endpoints.get(endpoint_id)
    if endpoint is None:
        return _fail("terminate_synthetic_process", target, "ENDPOINT_NOT_FOUND")
    process = next((p for p in endpoint.processes if p.pid == int(process_id)), None)
    if process is None:
        return _fail("terminate_synthetic_process", target, "PROCESS_NOT_FOUND")
    if process.status != "running":
        return _fail("terminate_synthetic_process", target, "PROCESS_NOT_RUNNING")

    process.status = "terminated"
    _record(env, "terminate_synthetic_process", target)
    return _ok("terminate_synthetic_process", target, f"Process {process.name} terminated")


def remove_persistence_entry(
    env: CyberEnvironment, endpoint_id: str, entry_id: str
) -> Dict[str, Any]:
    target = f"{endpoint_id}:{entry_id}"
    halted = _halted(env, "remove_persistence_entry", target)
    if halted:
        return halted

    endpoint = env.state.endpoints.get(endpoint_id)
    if endpoint is None:
        return _fail("remove_persistence_entry", target, "ENDPOINT_NOT_FOUND")
    entry = next((e for e in endpoint.persistence_entries if e.entry_id == entry_id), None)
    if entry is None:
        return _fail("remove_persistence_entry", target, "PERSISTENCE_ENTRY_NOT_FOUND")

    endpoint.persistence_entries.remove(entry)
    _record(env, "remove_persistence_entry", target)
    return _ok("remove_persistence_entry", target, f"Persistence entry {entry.name} removed")


def block_simulated_connection(env: CyberEnvironment, connection_id: str) -> Dict[str, Any]:
    halted = _halted(env, "block_simulated_connection", connection_id)
    if halted:
        return halted

    for endpoint in env.state.endpoints.values():
        for connection in endpoint.network_connections:
            if connection.connection_id == connection_id:
                if connection.state == "blocked":
                    return _fail(
                        "block_simulated_connection", connection_id, "CONNECTION_ALREADY_BLOCKED"
                    )
                connection.state = "blocked"
                _record(env, "block_simulated_connection", connection_id)
                return _ok(
                    "block_simulated_connection",
                    connection_id,
                    f"Connection from {endpoint.endpoint_id} blocked at the host firewall",
                )
    return _fail("block_simulated_connection", connection_id, "CONNECTION_NOT_FOUND")


def protect_data_asset(env: CyberEnvironment, asset_id: str) -> Dict[str, Any]:
    """Put a data store behind an emergency policy: further access is refused."""
    halted = _halted(env, "protect_data_asset", asset_id)
    if halted:
        return halted

    asset = env.state.assets.get(asset_id)
    if asset is None:
        return _fail("protect_data_asset", asset_id, "ASSET_NOT_FOUND")
    if asset.restricted:
        return _fail("protect_data_asset", asset_id, "ASSET_ALREADY_PROTECTED")

    asset.restricted = True
    asset.exposed = False
    asset.recent_activity.append("emergency data-access policy applied")
    _record(env, "protect_data_asset", asset_id)
    return _ok("protect_data_asset", asset_id, "Data asset protected; further access refused")
