"""Phase 1 demo: build the Nexora Systems environment, print it, verify reset().

Run from the `backend/` directory:

    python3 run_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.models.environment import (  # noqa: E402  (path set up above)
    AlertStatus,
    BlockedIP,
    SessionStatus,
    TokenStatus,
)
from app.simulator.environment import CyberEnvironment  # noqa: E402

LINE_WIDTH = 78


def heading(title: str) -> None:
    print()
    print("=" * LINE_WIDTH)
    print(title)
    print("=" * LINE_WIDTH)


def clock(timestamp: str) -> str:
    """Strip the date and offset from an ISO timestamp for compact printing."""
    return timestamp[11:19]


def fingerprint(state: Dict[str, Any]) -> str:
    """Stable serialization of a state snapshot, used to compare before/after."""
    return json.dumps(state, sort_keys=True, default=str)


def print_organization(state: Dict[str, Any]) -> None:
    org = state["organization"]
    heading(f"{org['name'].upper()} — {org['industry']}")
    print(f"  Domain          : {org['domain']}")
    print(f"  Headquarters    : {org['headquarters']}")
    print(f"  Offices         : {' | '.join(org['offices'])}")
    print(f"  Employees       : {org['employee_count']}")
    print(f"  Scenario        : {state['scenario']}")
    print(f"  Simulation time : {state['simulation_time']}")

    print("\n  Users")
    for user in state["users"].values():
        print(
            f"    - {user['user_id']:<12} {user['full_name']:<12} "
            f"{user['role']:<19} {user['office_location']:<19} {user['access_level']}"
        )

    print("\n  Assets")
    for asset in state["assets"].values():
        print(
            f"    - {asset['asset_id']:<19} {asset['asset_type']:<15} "
            f"criticality={asset['criticality']:<12} class={asset['data_classification']}"
        )


def print_sessions(state: Dict[str, Any]) -> None:
    heading("ACTIVE SESSIONS")
    active = [s for s in state["sessions"].values() if s["status"] == SessionStatus.ACTIVE]
    for session in sorted(active, key=lambda s: s["started_at"]):
        geo = session["geo"]
        print(
            f"  {session['session_id']:<10} {session['user_id']:<12} "
            f"{geo['city'] + ', ' + geo['country_code']:<20} started {clock(session['started_at'])}"
        )
        print(
            f"    ip={session['source_ip']:<16} device={session['device_id']:<18} "
            f"managed={str(session['device_managed']):<5} mfa={session['auth_method']}"
        )
        print(f"    asn={session['asn']}  network={session['network_type']}")


def print_tokens(state: Dict[str, Any]) -> None:
    heading("ACTIVE TOKENS")
    active = [t for t in state["tokens"].values() if t["status"] == TokenStatus.ACTIVE]
    for token in sorted(active, key=lambda t: t["issued_at"]):
        print(
            f"  {token['token_id']:<12} owner={token['owner']:<12} "
            f"client={token['client_name']:<20} issued={token['issued_at']}"
        )
        print(
            f"    permissions={', '.join(token['permissions'])}  "
            f"consent_prompt_shown={token['consent_prompt_shown']}"
        )


def print_alerts(state: Dict[str, Any]) -> None:
    heading("SECURITY ALERTS")
    for alert in state["security_alerts"]:
        print(
            f"  [{alert['severity'].upper():<8}] {clock(alert['timestamp'])} "
            f"{alert['alert_id']}  {alert['title']}  ({alert['rule_id']}, {alert['status']})"
        )
        print(f"    source={alert['source']}  users={', '.join(alert['related_users'])}")
        print(f"    assets={', '.join(alert['related_assets'])}")
        for key, value in alert["evidence"].items():
            if isinstance(value, dict):
                value = "{" + ", ".join(f"{k}={v}" for k, v in value.items()) + "}"
            elif isinstance(value, list):
                value = ", ".join(str(item) for item in value)
            print(f"      {key}: {value}")
        print()


def print_latest_events(state: Dict[str, Any], limit: int = 6) -> None:
    heading(f"LATEST EVENTS (most recent {limit} across all sources)")
    events: List[Dict[str, Any]] = []
    for event in state["authentication_events"]:
        events.append(
            {
                "timestamp": event["timestamp"],
                "source": "identity",
                "id": event["event_id"],
                "summary": (
                    f"{event['user_id']} {event['event_type']} -> {event['outcome']} "
                    f"from {event['source_ip']} ({event['geo']['city']})"
                ),
            }
        )
    for event in state["cloud_events"]:
        events.append(
            {
                "timestamp": event["timestamp"],
                "source": "cloud",
                "id": event["event_id"],
                "summary": (
                    f"{event['actor']} {event['action']} on {event['asset_id']} "
                    f"-> {event['outcome']} (token {event['token_id']})"
                ),
            }
        )
    for event in state["network_events"]:
        events.append(
            {
                "timestamp": event["timestamp"],
                "source": "network",
                "id": event["event_id"],
                "summary": (
                    f"{event['source_ip']} -> {event['destination_asset']}"
                    f":{event['destination_port']} {event['action']}"
                ),
            }
        )
    for event in sorted(events, key=lambda e: e["timestamp"])[-limit:]:
        print(
            f"  {clock(event['timestamp'])}  {event['source']:<9} "
            f"{event['id']:<12} {event['summary']}"
        )


def print_status(state: Dict[str, Any]) -> None:
    incident = state["incident_status"]
    heading("ENVIRONMENT STATUS")
    print(f"  Incident        : {incident['incident_id']}")
    print(f"  Status          : {incident['status']}")
    print(f"  Severity        : {incident['severity']}")
    print(f"  Declared        : {incident['declared_at']} by {incident['declared_by']}")
    print(
        f"  Open alerts     : {incident['open_alert_count']} "
        f"(highest {incident['highest_alert_severity']})"
    )
    print(f"  Containment     : {incident['containment_actions'] or 'none taken'}")
    print(f"  Blocked IPs     : {[b['ip_address'] for b in state['blocked_ips']]}")
    for note in incident["notes"]:
        print(f"  Note            : {note}")


def verify_reset(env: CyberEnvironment) -> bool:
    """Mutate the estate, confirm the change lands, then confirm reset() undoes it."""
    heading("RESET VERIFICATION")
    baseline = fingerprint(env.get_state())

    state = env.state
    state.sessions["sess-1002"].status = SessionStatus.TERMINATED
    state.tokens["oauth-8492"].status = TokenStatus.REVOKED
    state.security_alerts[0].status = AlertStatus.ACKNOWLEDGED
    state.blocked_ips.append(
        BlockedIP(
            ip_address="185.220.101.47",
            reason="Manual containment during reset verification",
            blocked_at="2026-03-11T17:40:00+05:30",
            blocked_by="run_demo",
            scope="global",
        )
    )
    state.incident_status.containment_actions.append("terminated sess-1002")

    mutated = fingerprint(env.get_state())
    mutation_took_effect = mutated != baseline
    print(f"  Mutations applied and visible in get_state()      : {mutation_took_effect}")

    env.reset()
    restored = fingerprint(env.get_state())
    reset_restored_baseline = restored == baseline
    print(f"  reset() restored the exact initial state          : {reset_restored_baseline}")

    rebuilt = fingerprint(CyberEnvironment(env.scenario).get_state())
    deterministic_across_instances = rebuilt == baseline
    print(f"  A fresh CyberEnvironment matches byte-for-byte    : {deterministic_across_instances}")

    snapshot = env.get_state()
    snapshot["security_alerts"].clear()
    snapshot_is_isolated = len(env.get_state()["security_alerts"]) == 5
    print(f"  get_state() snapshots are isolated copies         : {snapshot_is_isolated}")

    return all(
        [
            mutation_took_effect,
            reset_restored_baseline,
            deterministic_across_instances,
            snapshot_is_isolated,
        ]
    )


def main() -> int:
    env = CyberEnvironment("credential_compromise")
    state = env.get_state()

    print_organization(state)
    print_sessions(state)
    print_tokens(state)
    print_alerts(state)
    print_latest_events(state)
    print_status(state)

    passed = verify_reset(env)

    heading("DEMO RESULT")
    print("  PASS — environment is deterministic and reset() is exact." if passed else
          "  FAIL — see the reset verification output above.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
