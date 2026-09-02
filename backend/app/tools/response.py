"""Simulated defensive actions. Each one mutates the live environment state."""

from __future__ import annotations

from typing import Any, Dict

from app.models.environment import BlockedIP, SessionStatus, TokenStatus
from app.simulator.environment import CyberEnvironment

# Fault flag consumed by revoke_token; deterministic, never random.
IAM_FAULT = "iam_service_unavailable"
IAM_FAULT_TOKEN = "oauth-8492"


def _ok(action: str, target: str, message: str) -> Dict[str, Any]:
    return {"success": True, "action": action, "target": target, "message": message}


def _fail(action: str, target: str, error: str) -> Dict[str, Any]:
    return {"success": False, "action": action, "target": target, "error": error}


def _record(env: CyberEnvironment, action: str, target: str) -> None:
    env.state.incident_status.containment_actions.append(f"{action}:{target}")


def revoke_token(env: CyberEnvironment, token_id: str) -> Dict[str, Any]:
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
    user = env.state.users.get(user_id)
    if user is None:
        return _fail("disable_user", user_id, "USER_NOT_FOUND")
    if user.status == "disabled":
        return _fail("disable_user", user_id, "USER_ALREADY_DISABLED")

    user.status = "disabled"
    _record(env, "disable_user", user_id)
    return _ok("disable_user", user_id, "Account disabled pending credential reset")


def terminate_session(env: CyberEnvironment, session_id: str) -> Dict[str, Any]:
    session = env.state.sessions.get(session_id)
    if session is None:
        return _fail("terminate_session", session_id, "SESSION_NOT_FOUND")
    if session.status is not SessionStatus.ACTIVE:
        return _fail("terminate_session", session_id, "SESSION_NOT_ACTIVE")

    session.status = SessionStatus.TERMINATED
    _record(env, "terminate_session", session_id)
    return _ok("terminate_session", session_id, "Session terminated")


def block_ip(env: CyberEnvironment, ip_address: str) -> Dict[str, Any]:
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
    asset = env.state.assets.get(asset_id)
    if asset is None:
        return _fail("restrict_asset", asset_id, "ASSET_NOT_FOUND")
    if asset.status == "restricted":
        return _fail("restrict_asset", asset_id, "ASSET_ALREADY_RESTRICTED")

    asset.status = "restricted"
    _record(env, "restrict_asset", asset_id)
    return _ok("restrict_asset", asset_id, "Asset placed under restricted access")
