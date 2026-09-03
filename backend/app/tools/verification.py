"""Derive containment state and a risk score from the current environment.

Nothing is read from a ground-truth label: suspicious sessions, live attacker
tokens and exposed assets are all inferred from evidence in the state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from app.models.environment import (
    AlertStatus,
    AssetCriticality,
    EnvironmentStatus,
    SessionStatus,
    Severity,
    TokenStatus,
)
from app.simulator.environment import CyberEnvironment

WEIGHTS = {
    "suspicious_session": 16,
    "compromised_token": 22,
    "exposed_crown_jewel": 14,
    "exposed_asset": 4,
    "unblocked_hostile_ip": 6,
    "compromised_principal": 8,
    "open_critical_alert": 4,
}


def _is_suspicious(env: CyberEnvironment, session) -> bool:
    """A session is suspicious when its own telemetry contradicts the account."""
    user = env.state.users.get(session.user_id)
    reasons = (
        not session.device_managed,
        session.network_type == "hosting_provider",
        user is not None and session.geo.country_code != user.home_country,
    )
    return sum(bool(r) for r in reasons) >= 2


def verify_environment(env: CyberEnvironment) -> Dict[str, Any]:
    state = env.state
    threats: List[Dict[str, str]] = []

    # 1. Active sessions whose evidence does not match the account baseline.
    suspicious_sessions = [
        s
        for s in state.sessions.values()
        if s.status is SessionStatus.ACTIVE and _is_suspicious(env, s)
    ]
    hostile_ips: Set[str] = {s.source_ip for s in suspicious_sessions}
    hostile_ips.update(e.source_ip for e in state.network_events if e.action == "denied")

    # 2. Tokens still live that were minted from a hostile source. A token whose
    #    owner is disabled cannot be exchanged, so it is no longer a live path.
    def _owner_enabled(owner: str) -> bool:
        user = state.users.get(owner)
        return user is None or user.status == "enabled"

    compromised_tokens = [
        t
        for t in state.tokens.values()
        if t.status is TokenStatus.ACTIVE
        and _owner_enabled(t.owner)
        and (t.issued_from_ip in hostile_ips or not t.consent_prompt_shown)
    ]

    live_path = bool(suspicious_sessions or compromised_tokens)

    # 3. Assets named by open critical alerts that remain reachable on a live path.
    exposed_assets = []
    if live_path:
        named: Set[str] = set()
        for alert in state.security_alerts:
            if alert.status is AlertStatus.OPEN and alert.severity is Severity.CRITICAL:
                named.update(alert.related_assets)
        exposed_assets = [
            state.assets[a]
            for a in sorted(named)
            if a in state.assets and state.assets[a].status == "online"
        ]

    # 4. Principals whose credentials were exercised from a hostile source.
    principals = sorted(
        {s.user_id for s in suspicious_sessions}
        | {t.owner for t in compromised_tokens if t.issued_from_ip in hostile_ips}
    )
    compromised_principals = [
        p for p in principals if state.users.get(p) and state.users[p].status == "enabled"
    ]

    unblocked = sorted(hostile_ips - {b.ip_address for b in state.blocked_ips})
    open_critical = [
        a
        for a in state.security_alerts
        if a.status is AlertStatus.OPEN and a.severity is Severity.CRITICAL
    ]

    score = 0
    for s in suspicious_sessions:
        score += WEIGHTS["suspicious_session"]
        threats.append(
            {
                "type": "SUSPICIOUS_SESSION",
                "target": s.session_id,
                "detail": f"{s.user_id} active from {s.geo.city} ({s.source_ip})",
            }
        )
    for t in compromised_tokens:
        score += WEIGHTS["compromised_token"]
        threats.append(
            {
                "type": "COMPROMISED_TOKEN",
                "target": t.token_id,
                "detail": f"active token for {t.owner} issued from {t.issued_from_ip}",
            }
        )
    for a in exposed_assets:
        crown = a.criticality is AssetCriticality.CROWN_JEWEL
        score += WEIGHTS["exposed_crown_jewel"] if crown else WEIGHTS["exposed_asset"]
        threats.append(
            {
                "type": "EXPOSED_ASSET",
                "target": a.asset_id,
                "detail": f"{a.criticality.value} asset reachable on a live path",
            }
        )
    for ip in unblocked:
        score += WEIGHTS["unblocked_hostile_ip"]
        threats.append(
            {"type": "UNBLOCKED_SOURCE", "target": ip, "detail": "hostile source not blocked"}
        )
    for p in compromised_principals:
        score += WEIGHTS["compromised_principal"]
        threats.append(
            {
                "type": "EXPOSED_CREDENTIALS",
                "target": p,
                "detail": "account enabled after use from a hostile source",
            }
        )
    score += WEIGHTS["open_critical_alert"] * len(open_critical)

    risk_score = max(0, min(100, score))
    contained = not suspicious_sessions and not compromised_tokens and not unblocked

    incident = state.incident_status
    incident.status = EnvironmentStatus.CONTAINED if contained else EnvironmentStatus.COMPROMISED
    incident.severity = Severity.MEDIUM if contained else Severity.CRITICAL

    return {
        "contained": contained,
        "risk_score": risk_score,
        "status": incident.status.value,
        "remaining_threats": threats,
        "suspicious_sessions": [s.session_id for s in suspicious_sessions],
        "active_compromised_tokens": [t.token_id for t in compromised_tokens],
        "exposed_critical_assets": [a.asset_id for a in exposed_assets],
        "unblocked_hostile_ips": unblocked,
        "open_critical_alerts": [a.alert_id for a in open_critical],
        "containment_actions": list(incident.containment_actions),
    }
