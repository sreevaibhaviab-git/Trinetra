"""Derive containment state and risk from the current environment.

Nothing here reads a ground-truth label. Suspicious sessions, live attacker
tokens, hiding mailbox rules and staged data are all inferred from evidence
that a real SOC would also have: device management, network type, geography,
consent records, rule shape, query volume and egress size.

The Red Engine's hidden state is never consulted — `state.hidden` does not
appear anywhere in this module.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from app.models.environment import (
    AlertStatus,
    AssetCriticality,
    EnvironmentStatus,
    EventOutcome,
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

# Per-domain evidence weights. Each domain is capped at 100.
DOMAIN_WEIGHTS = {
    "session": 30,
    "token": 30,
    "device": 20,
    "principal": 20,
    "mailbox_rule": 40,
    "mailbox_search": 15,
    "bulk_drive_access": 20,
    "privileged_role": 35,
    "repo_clone_burst": 25,
    "exposed_asset": 10,
    "bulk_read": 45,
    "staging_write": 25,
    "egress": 30,
    "live_egress_endpoint": 40,
    "unsigned_process": 15,
    "unknown_domain": 15,
}

# The blend that produces the headline risk score.
DOMAIN_BLEND = {
    "identity_risk": 0.25,
    "endpoint_risk": 0.15,
    "saas_risk": 0.15,
    "cloud_risk": 0.20,
    "data_risk": 0.25,
}

HIDING_ACTIONS = ("mark_as_read", "delete", "move_to:RSS Feeds", "move_to:Deleted Items")


def _is_suspicious(env: CyberEnvironment, session) -> bool:
    """A session is suspicious when its own telemetry contradicts the account."""
    user = env.state.users.get(session.user_id)
    reasons = (
        not session.device_managed,
        session.network_type == "hosting_provider",
        user is not None and session.geo.country_code != user.home_country,
    )
    return sum(bool(r) for r in reasons) >= 2


def _is_dangerous_rule(rule) -> bool:
    """A rule that hides mail it matches, or hides behind a one-character name."""
    hides = any(action in HIDING_ACTIONS for action in rule.actions)
    return rule.enabled and (hides or len(rule.name.strip()) <= 2)


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

    # 2. Tokens still live that were minted from a hostile source or without a
    #    consent record. A disabled owner cannot exchange one, so it is dead.
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

    # 3. Devices enrolled against an account that management never vouched for.
    suspicious_devices = [
        d for d in state.devices.values() if not d.managed or not d.compliant
    ]

    # 4. Assets named by open critical alerts that remain reachable on a live path.
    exposed_assets = []
    if live_path:
        named: Set[str] = set()
        for alert in state.security_alerts:
            if alert.status is AlertStatus.OPEN and alert.severity is Severity.CRITICAL:
                named.update(alert.related_assets)
        exposed_assets = [
            state.assets[a]
            for a in sorted(named)
            if a in state.assets
            and state.assets[a].status == "online"
            and not state.assets[a].restricted
        ]

    # 5. Principals whose credentials were exercised from a hostile source.
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

    # 6. SaaS: hiding inbox rules, search bursts and bulk document pulls.
    dangerous_rules = [r for r in state.mailbox_rules if _is_dangerous_rule(r)]
    mailbox_searches = [e for e in state.mailbox_events if e.event_type == "mailbox_search"]
    bulk_drive = [
        e
        for e in state.drive_events
        if e.action == "download" and e.sensitivity in ("confidential", "restricted")
    ]

    # 7. Cloud: privileged roles taken outside the usual credential path, and
    #    clone bursts well outside the actor's own baseline.
    privileged_roles = [
        e
        for e in state.cloud_events
        if e.action == "sts:AssumeRole"
        and e.outcome is EventOutcome.SUCCESS
        and e.details.get("actor_prior_assumptions_180d") == 0
    ]
    clone_bursts = [
        e
        for e in state.cloud_events
        if e.action == "repo.clone" and e.details.get("repository_count", 0) >= 3
    ]

    # 8. Data: successful bulk reads of restricted stores, staging writes and
    #    the egress that would carry them out. Protected assets drop out.
    bulk_reads = [
        e
        for e in state.cloud_events
        if e.outcome is EventOutcome.SUCCESS
        and e.details.get("rows_returned", 0) >= 1000
        and not state.assets.get(e.asset_id, state.assets["aws"]).restricted
    ]
    staging_writes = [
        e
        for e in state.cloud_events
        if e.action == "s3:PutObject" and e.details.get("bucket_created_minutes_ago", 999) < 60
    ]
    egress = [
        t for t in state.outbound_transfer_events if t.classification == "customer_records"
    ]
    # 9. Endpoints: an endpoint still on the network after carrying egress.
    egress_endpoints = {t.source_endpoint for t in egress}
    live_egress_endpoints = [
        e
        for e in state.endpoints.values()
        if e.endpoint_id in egress_endpoints and not e.isolated
    ]

    # Only data exposure someone can still act on counts as active: a read or a
    # staging write matters while a live path remains, egress while the endpoint
    # that carried it is still on the network.
    active_data_risk = sorted(
        ({e.asset_id for e in bulk_reads} if live_path else set())
        | ({"aws"} if staging_writes and live_path else set())
        | ({"api-gateway"} if live_egress_endpoints else set())
    )

    isolated_endpoints = [e.endpoint_id for e in state.endpoints.values() if e.isolated]
    unsigned_processes = [
        p
        for e in state.endpoints.values()
        for p in e.processes
        if not p.signed and p.status == "running"
    ]
    unknown_domains = [
        d
        for d in state.dns_events
        if d.category == "uncategorised"
        and not getattr(state.endpoints.get(d.source_endpoint), "isolated", False)
    ]

    # ---- domain scores, each capped at 100 ------------------------------
    # Every *_risk means *active* risk: 0 is nothing left to act on, 100 is the
    # maximum. Past events stay in telemetry forever, but they only carry risk
    # while the path that produced them is still open — a search burst or a
    # clone burst is history once no session or token can repeat it.
    def _cap(value: int) -> int:
        return max(0, min(100, value))

    def _while_live(count: int) -> int:
        return count if live_path else 0

    identity_risk = _cap(
        DOMAIN_WEIGHTS["session"] * len(suspicious_sessions)
        + DOMAIN_WEIGHTS["token"] * len(compromised_tokens)
        + DOMAIN_WEIGHTS["device"] * len(suspicious_devices)
        + DOMAIN_WEIGHTS["principal"] * len(compromised_principals)
    )
    endpoint_risk = _cap(
        DOMAIN_WEIGHTS["live_egress_endpoint"] * len(live_egress_endpoints)
        + DOMAIN_WEIGHTS["unknown_domain"] * _while_live(len(unknown_domains))
        + DOMAIN_WEIGHTS["unsigned_process"] * len(unsigned_processes)
    )
    saas_risk = _cap(
        DOMAIN_WEIGHTS["mailbox_rule"] * len(dangerous_rules)
        + DOMAIN_WEIGHTS["mailbox_search"] * _while_live(min(len(mailbox_searches), 3))
        + DOMAIN_WEIGHTS["bulk_drive_access"] * _while_live(min(len(bulk_drive), 2))
    )
    cloud_risk = _cap(
        DOMAIN_WEIGHTS["privileged_role"] * _while_live(len(privileged_roles))
        + DOMAIN_WEIGHTS["repo_clone_burst"] * _while_live(len(clone_bursts))
        + DOMAIN_WEIGHTS["exposed_asset"] * len(exposed_assets)
    )
    data_risk = _cap(
        DOMAIN_WEIGHTS["bulk_read"] * _while_live(len(bulk_reads))
        + DOMAIN_WEIGHTS["staging_write"] * _while_live(len(staging_writes))
        + DOMAIN_WEIGHTS["egress"] * (len(egress) if live_egress_endpoints else 0)
    )
    domains = {
        "identity_risk": identity_risk,
        "endpoint_risk": endpoint_risk,
        "saas_risk": saas_risk,
        "cloud_risk": cloud_risk,
        "data_risk": data_risk,
    }

    # ---- legacy live-path score, kept so earlier phases still read it ----
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
    for d in suspicious_devices:
        threats.append(
            {
                "type": "SUSPICIOUS_DEVICE",
                "target": d.device_id,
                "detail": f"unmanaged device enrolled against {d.owner}",
            }
        )
    for r in dangerous_rules:
        threats.append(
            {
                "type": "DANGEROUS_MAILBOX_RULE",
                "target": r.rule_id,
                "detail": f"rule on {r.mailbox} hides matching mail ({', '.join(r.actions)})",
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
    for endpoint in live_egress_endpoints:
        threats.append(
            {
                "type": "ACTIVE_EGRESS_PATH",
                "target": endpoint.endpoint_id,
                "detail": "endpoint carried a bulk transfer and is still on the network",
            }
        )
    for asset_id in active_data_risk:
        threats.append(
            {
                "type": "ACTIVE_DATA_RISK",
                "target": asset_id,
                "detail": "restricted data read or staged and not yet protected",
            }
        )
    # Open detections are history once nothing can act on them; they stay in the
    # alert list either way, they just stop carrying risk.
    if live_path:
        score += WEIGHTS["open_critical_alert"] * len(open_critical)

    blended = sum(domains[name] * weight for name, weight in DOMAIN_BLEND.items())
    risk_score = _cap(round(max(blended, min(score, 100))))
    contained = not (
        suspicious_sessions
        or compromised_tokens
        or unblocked
        or dangerous_rules
        or live_egress_endpoints
        or active_data_risk
    )

    incident = state.incident_status
    if not contained:
        incident.status = EnvironmentStatus.COMPROMISED
        incident.severity = Severity.CRITICAL
    elif incident.containment_actions:
        incident.status = EnvironmentStatus.CONTAINED
        incident.severity = Severity.MEDIUM

    return {
        "contained": contained,
        "risk_score": risk_score,
        "resilience_score": state.safety.resilience_score,
        "status": incident.status.value,
        **domains,
        "active_suspicious_sessions": [s.session_id for s in suspicious_sessions],
        "active_risky_tokens": [t.token_id for t in compromised_tokens],
        "suspicious_devices": [d.device_id for d in suspicious_devices],
        "dangerous_mailbox_rules": [r.rule_id for r in dangerous_rules],
        "isolated_endpoints": isolated_endpoints,
        "exposed_critical_assets": [a.asset_id for a in exposed_assets],
        "active_data_risk": active_data_risk,
        "remaining_threats": threats,
        # Retained names so Phase 2 callers keep working unchanged.
        "suspicious_sessions": [s.session_id for s in suspicious_sessions],
        "active_compromised_tokens": [t.token_id for t in compromised_tokens],
        "unblocked_hostile_ips": unblocked,
        "open_critical_alerts": [a.alert_id for a in open_critical],
        "containment_actions": list(incident.containment_actions),
    }
