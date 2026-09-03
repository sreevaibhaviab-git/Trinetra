"""Allowlisted tool surface exposed to the model.

Only the Phase 2 functions appear here. Anything the model asks for that is not
in `REGISTRY`, or any argument that is not declared, is refused before it can
reach the environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

from app.simulator.environment import CyberEnvironment
from app.tools import (
    block_ip,
    disable_user,
    get_active_sessions,
    get_asset_status,
    get_cloud_activity,
    get_environment_summary,
    get_network_activity,
    get_recent_logins,
    get_tokens,
    restrict_asset,
    revoke_token,
    terminate_session,
    verify_environment,
)

Kind = str  # "investigation" | "defensive" | "verification"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: Kind
    description: str
    fn: Callable[..., Any]
    params: Dict[str, str]  # arg name -> "string" | "integer"
    required: Tuple[str, ...] = ()


REGISTRY: Dict[str, ToolSpec] = {
    t.name: t
    for t in (
        ToolSpec(
            "get_environment_summary",
            "investigation",
            "High-level posture of the estate: counts, incident status, open alerts, blocked IPs.",
            get_environment_summary,
            {},
        ),
        ToolSpec(
            "get_recent_logins",
            "investigation",
            "Sign-in events with source IP, geo, device and MFA detail. Optionally filter by user.",
            get_recent_logins,
            {"user_id": "string", "limit": "integer"},
        ),
        ToolSpec(
            "get_active_sessions",
            "investigation",
            "Currently active sessions with device, network and geo attribution.",
            get_active_sessions,
            {"user_id": "string"},
        ),
        ToolSpec(
            "get_tokens",
            "investigation",
            "OAuth and personal access tokens with permissions, issuing session and consent record.",
            get_tokens,
            {"user_id": "string"},
        ),
        ToolSpec(
            "get_cloud_activity",
            "investigation",
            "Audited SaaS and cloud control-plane actions. Optionally filter by actor.",
            get_cloud_activity,
            {"user_id": "string"},
        ),
        ToolSpec(
            "get_network_activity",
            "investigation",
            "Edge flow records including allowed and denied connections. Optionally filter by asset.",
            get_network_activity,
            {"asset_id": "string"},
        ),
        ToolSpec(
            "get_asset_status",
            "investigation",
            "Detail for one asset: criticality, status, open alerts and event counts.",
            get_asset_status,
            {"asset_id": "string"},
            ("asset_id",),
        ),
        ToolSpec(
            "verify_environment",
            "verification",
            "Re-derive containment state: contained flag, risk score and remaining threats.",
            verify_environment,
            {},
        ),
        ToolSpec(
            "revoke_token",
            "defensive",
            "Revoke an OAuth or access token so it can no longer be used.",
            revoke_token,
            {"token_id": "string"},
            ("token_id",),
        ),
        ToolSpec(
            "terminate_session",
            "defensive",
            "Terminate one active session.",
            terminate_session,
            {"session_id": "string"},
            ("session_id",),
        ),
        ToolSpec(
            "block_ip",
            "defensive",
            "Block a source IP address at the network edge.",
            block_ip,
            {"ip_address": "string"},
            ("ip_address",),
        ),
        ToolSpec(
            "disable_user",
            "defensive",
            "Disable a user account. Disruptive: the person loses all access.",
            disable_user,
            {"user_id": "string"},
            ("user_id",),
        ),
        ToolSpec(
            "restrict_asset",
            "defensive",
            "Place an asset under restricted access. Highly disruptive for production assets.",
            restrict_asset,
            {"asset_id": "string"},
            ("asset_id",),
        ),
    )
}


def function_declarations() -> List[Any]:
    """Gemini FunctionDeclaration objects for every allowlisted tool."""
    from google.genai import types

    declarations = []
    for spec in REGISTRY.values():
        schema: Dict[str, Any] = {"type": "OBJECT", "properties": {}}
        for arg, arg_type in spec.params.items():
            schema["properties"][arg] = {"type": arg_type.upper()}
        if spec.required:
            schema["required"] = list(spec.required)
        declarations.append(
            types.FunctionDeclaration(
                name=spec.name,
                description=spec.description,
                parameters=schema if spec.params else None,
            )
        )
    return declarations


def call_tool(env: CyberEnvironment, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate then execute an allowlisted tool. Never raises."""
    spec = REGISTRY.get(name)
    if spec is None:
        return {"success": False, "error": "UNKNOWN_TOOL", "detail": f"{name} is not available"}

    args = dict(args or {})
    unexpected = [a for a in args if a not in spec.params]
    if unexpected:
        return {
            "success": False,
            "error": "INVALID_ARGUMENTS",
            "detail": f"unexpected argument(s): {', '.join(sorted(unexpected))}",
        }
    missing = [a for a in spec.required if args.get(a) in (None, "")]
    if missing:
        return {
            "success": False,
            "error": "INVALID_ARGUMENTS",
            "detail": f"missing required argument(s): {', '.join(missing)}",
        }

    clean: Dict[str, Any] = {}
    for arg, value in args.items():
        if value is None:
            continue
        if spec.params[arg] == "integer":
            try:
                clean[arg] = int(value)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "error": "INVALID_ARGUMENTS",
                    "detail": f"{arg} must be an integer",
                }
        else:
            if not isinstance(value, (str, int, float)):
                return {
                    "success": False,
                    "error": "INVALID_ARGUMENTS",
                    "detail": f"{arg} must be a string",
                }
            clean[arg] = str(value)

    try:
        return {"success": True, "result": spec.fn(env, **clean)}
    except Exception as exc:  # tool bugs must not kill the run
        return {"success": False, "error": "TOOL_EXECUTION_ERROR", "detail": str(exc)}


def target_of(name: str, args: Dict[str, Any]) -> str:
    """Best-effort single-value target for event display."""
    spec = REGISTRY.get(name)
    if not spec or not args:
        return ""
    for arg in (spec.required or tuple(spec.params)):
        value = args.get(arg)
        if value:
            return str(value)
    return ""
