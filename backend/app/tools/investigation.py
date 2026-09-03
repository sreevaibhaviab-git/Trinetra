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


def _since(events: List[Dict[str, Any]], since: Optional[str], key: str = "timestamp"):
    """Keep events at or after an ISO timestamp (or a bare HH:MM:SS clock)."""
    if not since:
        return events
    return [e for e in events if e[key][11:19] >= since[-8:]]


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
    env: CyberEnvironment,
    endpoint_id: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Edge flows, plus the endpoint's own sockets and egress when one is named."""
    events = list(env.state.network_events)
    if asset_id:
        events = [e for e in events if e.destination_asset == asset_id]
    events.sort(key=lambda e: e.timestamp)
    result = [_d(e) for e in events]
    if endpoint_id:
        endpoint = env.state.endpoints.get(endpoint_id)
        if endpoint is None:
            return [{"success": False, "error": "ENDPOINT_NOT_FOUND", "target": endpoint_id}]
        result = [_d(c) for c in endpoint.network_connections]
        result += [
            _d(t) for t in env.state.outbound_transfer_events if t.source_endpoint == endpoint_id
        ]
    return result


# -- identity ------------------------------------------------------------


def get_registered_devices(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    devices = list(env.state.devices.values())
    if user_id:
        devices = [d for d in devices if d.owner == user_id]
    devices.sort(key=lambda d: d.enrolled_at)
    return [_d(d) for d in devices]


def get_oauth_activity(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> Dict[str, Any]:
    """Standing consents, live tokens and the authorization events behind them."""
    grants = list(env.state.oauth_grants.values())
    tokens = list(env.state.tokens.values())
    events = [
        e
        for e in env.state.authentication_events
        if e.event_type in ("oauth_token_issued", "device_code_authorization_requested")
    ]
    if user_id:
        grants = [g for g in grants if g.user_id == user_id]
        tokens = [t for t in tokens if t.owner == user_id]
        events = [e for e in events if e.user_id == user_id]
    return {
        "grants": [_d(g) for g in sorted(grants, key=lambda g: g.granted_at)],
        "tokens": [_d(t) for t in sorted(tokens, key=lambda t: t.issued_at)],
        "authorization_events": [_d(e) for e in sorted(events, key=lambda e: e.timestamp)],
    }


# -- SaaS ----------------------------------------------------------------


def _mailbox_of(env: CyberEnvironment, user_id: Optional[str]) -> Optional[str]:
    user = env.state.users.get(user_id) if user_id else None
    return user.email if user else None


def get_mailbox_activity(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = list(env.state.mailbox_events)
    mailbox = _mailbox_of(env, user_id)
    if mailbox:
        events = [e for e in events if e.mailbox == mailbox]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


def get_mailbox_rules(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    rules = list(env.state.mailbox_rules)
    mailbox = _mailbox_of(env, user_id)
    if mailbox:
        rules = [r for r in rules if r.mailbox == mailbox]
    return [_d(r) for r in sorted(rules, key=lambda r: r.created_at)]


def get_cloud_drive_activity(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = list(env.state.drive_events)
    if user_id:
        events = [e for e in events if e.actor == user_id]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


# -- endpoints -----------------------------------------------------------


def _endpoint(env: CyberEnvironment, endpoint_id: str):
    return env.state.endpoints.get(endpoint_id)


def get_endpoint_status(env: CyberEnvironment, endpoint_id: str) -> Dict[str, Any]:
    endpoint = _endpoint(env, endpoint_id)
    if endpoint is None:
        return {"success": False, "error": "ENDPOINT_NOT_FOUND", "target": endpoint_id}
    return {
        "endpoint_id": endpoint.endpoint_id,
        "hostname": endpoint.hostname,
        "owner": endpoint.owner,
        "os": f"{endpoint.os} {endpoint.os_version}",
        "status": endpoint.status,
        "isolated": endpoint.isolated,
        "managed": endpoint.managed,
        "last_seen": endpoint.last_seen,
        "processes": len(endpoint.processes),
        "files": len(endpoint.files),
        "applications": len(endpoint.applications),
        "browser_sessions": len(endpoint.browser_sessions),
        "network_connections": len(endpoint.network_connections),
        "persistence_entries": len(endpoint.persistence_entries),
        "downloads": len(endpoint.downloads),
    }


def get_process_activity(env: CyberEnvironment, endpoint_id: str) -> List[Dict[str, Any]]:
    endpoint = _endpoint(env, endpoint_id)
    if endpoint is None:
        return [{"success": False, "error": "ENDPOINT_NOT_FOUND", "target": endpoint_id}]
    return [_d(p) for p in endpoint.processes]


def get_file_activity(env: CyberEnvironment, endpoint_id: str) -> Dict[str, Any]:
    endpoint = _endpoint(env, endpoint_id)
    if endpoint is None:
        return {"success": False, "error": "ENDPOINT_NOT_FOUND", "target": endpoint_id}
    return {
        "files": [_d(f) for f in endpoint.files],
        "downloads": [_d(d) for d in endpoint.downloads],
    }


def get_persistence_entries(env: CyberEnvironment, endpoint_id: str) -> List[Dict[str, Any]]:
    endpoint = _endpoint(env, endpoint_id)
    if endpoint is None:
        return [{"success": False, "error": "ENDPOINT_NOT_FOUND", "target": endpoint_id}]
    return [_d(e) for e in endpoint.persistence_entries]


def get_dns_activity(
    env: CyberEnvironment, endpoint_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = list(env.state.dns_events)
    if endpoint_id:
        events = [e for e in events if e.source_endpoint == endpoint_id]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


# -- developer, cloud and data -------------------------------------------


def get_github_activity(
    env: CyberEnvironment, user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    events = [e for e in env.state.cloud_events if e.asset_id == "github"]
    if user_id:
        events = [e for e in events if e.actor == user_id]
    events.sort(key=lambda e: e.timestamp)
    return [_d(e) for e in events]


def get_data_access_activity(
    env: CyberEnvironment, asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """Reads and writes against data stores, with the egress that followed them."""
    data_assets = {
        a.asset_id
        for a in env.state.assets.values()
        if a.data_classification.startswith("restricted")
    }
    events = [
        e
        for e in env.state.cloud_events
        if e.asset_id in data_assets or e.service in ("rds", "s3")
    ]
    if asset_id:
        events = [e for e in events if e.asset_id == asset_id]
    return {
        "access_events": [_d(e) for e in sorted(events, key=lambda e: e.timestamp)],
        "outbound_transfers": [
            _d(t) for t in sorted(env.state.outbound_transfer_events, key=lambda t: t.timestamp)
        ],
    }


# -- detections and timeline ---------------------------------------------


def get_security_alerts(
    env: CyberEnvironment,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    since: Optional[str] = None,
) -> List[Dict[str, Any]]:
    alerts = [a for a in env.state.security_alerts if a.status is AlertStatus.OPEN]
    if severity:
        alerts = [a for a in alerts if a.severity.value == severity.lower()]
    if category:
        alerts = [a for a in alerts if a.source == category]
    records = [_d(a) for a in sorted(alerts, key=lambda a: a.timestamp)]
    return _since(records, since)


def get_timeline(
    env: CyberEnvironment,
    since: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 60,
) -> List[Dict[str, Any]]:
    """The unified telemetry bus: every observation, oldest first."""
    events = list(env.state.telemetry)
    if category:
        events = [
            e for e in events if category in (e.category, e.source.value, e.source.value.lower())
        ]
    records = [_d(e) for e in sorted(events, key=lambda e: e.timestamp)]
    return _since(records, since)[:limit]


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
