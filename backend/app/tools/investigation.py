"""Read-only tools for inspecting the simulated estate.

Every function takes the live `CyberEnvironment` and returns plain dictionaries,
so nothing here can mutate state by accident.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from app.models.environment import AlertStatus, SessionStatus, _plain
from app.simulator.environment import CyberEnvironment


def _d(obj: Any) -> Dict[str, Any]:
    return _plain(asdict(obj))


def get_recent_logins(
    env: CyberEnvironment, user_id: Optional[str] = None, limit: int = 10
) -> List[Dict[str, Any]]:
    events = [e for e in env.state.authentication_events if e.event_type == "user_login"]
    if user_id:
        events = [e for e in events if e.user_id == user_id]
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return [_d(e) for e in events[:limit]]


def get_active_sessions(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    sessions = [
        s for s in env.state.sessions.values() if s.status is SessionStatus.ACTIVE
    ]
    if user_id:
        sessions = [s for s in sessions if s.user_id == user_id]
    sessions.sort(key=lambda s: s.started_at)
    return [_d(s) for s in sessions]


def get_tokens(env: CyberEnvironment, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    tokens = list(env.state.tokens.values())
    if user_id:
        tokens = [t for t in tokens if t.owner == user_id]
    tokens.sort(key=lambda t: t.issued_at)
    return [_d(t) for t in tokens]


def get_cloud_activity(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = list(env.state.cloud_events)
    if user_id:
        events = [e for e in events if e.actor == user_id]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


def get_network_activity(
    env: CyberEnvironment, asset_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = list(env.state.network_events)
    if asset_id:
        events = [e for e in events if e.destination_asset == asset_id]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


def get_asset_status(env: CyberEnvironment, asset_id: str) -> Dict[str, Any]:
    asset = env.state.assets.get(asset_id)
    if asset is None:
        return {"success": False, "error": "ASSET_NOT_FOUND", "target": asset_id}

    open_alerts = [
        a
        for a in env.state.security_alerts
        if a.status is AlertStatus.OPEN and asset_id in a.related_assets
    ]
    return {
        "asset": _d(asset),
        "open_alerts": [
            {"alert_id": a.alert_id, "severity": a.severity.value, "title": a.title}
            for a in open_alerts
        ],
        "cloud_event_count": sum(1 for e in env.state.cloud_events if e.asset_id == asset_id),
        "network_event_count": sum(
            1 for e in env.state.network_events if e.destination_asset == asset_id
        ),
        "denied_network_events": sum(
            1
            for e in env.state.network_events
            if e.destination_asset == asset_id and e.action == "denied"
        ),
    }


def get_environment_summary(env: CyberEnvironment) -> Dict[str, Any]:
    state = env.state
    open_alerts = [a for a in state.security_alerts if a.status is AlertStatus.OPEN]
    severities: Dict[str, int] = {}
    for alert in open_alerts:
        severities[alert.severity.value] = severities.get(alert.severity.value, 0) + 1

    return {
        "organization": state.organization.name,
        "scenario": state.scenario,
        "simulation_time": state.simulation_time,
        "incident_id": state.incident_status.incident_id,
        "status": state.incident_status.status.value,
        "severity": state.incident_status.severity.value,
        "users": len(state.users),
        "disabled_users": sum(1 for u in state.users.values() if u.status != "enabled"),
        "assets": len(state.assets),
        "restricted_assets": sum(1 for a in state.assets.values() if a.status != "online"),
        "active_sessions": sum(
            1 for s in state.sessions.values() if s.status is SessionStatus.ACTIVE
        ),
        "active_tokens": sum(1 for t in state.tokens.values() if t.status.value == "active"),
        "open_alerts": len(open_alerts),
        "open_alerts_by_severity": severities,
        "blocked_ips": [b.ip_address for b in state.blocked_ips],
        "containment_actions": list(state.incident_status.containment_actions),
    }
