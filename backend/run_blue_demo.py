"""Phase 2B demo: investigating and containing Operation Maya with Blue tools.

No AI is involved — every step below is a human-scripted tool call.

Run from the `backend/` directory:

    python3 run_blue_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.simulator.environment import CyberEnvironment  # noqa: E402
from app.simulator.red_engine import RedAttackEngine  # noqa: E402
from app.tools import (  # noqa: E402
    BLUE_TOOL_REGISTRY,
    get_active_sessions,
    get_cloud_drive_activity,
    get_data_access_activity,
    get_environment_summary,
    get_github_activity,
    get_mailbox_rules,
    get_oauth_activity,
    get_recent_logins,
    get_registered_devices,
    isolate_endpoint,
    protect_data_asset,
    remove_mailbox_rule,
    remove_registered_device,
    revoke_token,
    verify_environment,
)

LINE = "=" * 70


def head(title: str) -> None:
    print(f"\n-- {title} " + "-" * max(0, 66 - len(title)))


def clock(ts: str) -> str:
    return ts[11:19]


def show_verification(label: str, v: dict) -> None:
    print(f"  {label}")
    print(f"    contained {v['contained']}   risk {v['risk_score']}   "
          f"resilience {v['resilience_score']}")
    print(f"    identity {v['identity_risk']}  endpoint {v['endpoint_risk']}  "
          f"saas {v['saas_risk']}  cloud {v['cloud_risk']}  data {v['data_risk']}")
    print(f"    remaining threats: {len(v['remaining_threats'])}")


def main() -> int:
    env = CyberEnvironment("nexora_baseline")
    red = RedAttackEngine(env)

    print(LINE)
    print("TRINETRA — BLUE INVESTIGATION")
    print(LINE)
    summary = get_environment_summary(env)
    print(f"Environment : {summary['scenario']}  {summary['status']}  "
          f"resilience {env.state.safety.resilience_score}")
    print(f"Blue tools  : {len(BLUE_TOOL_REGISTRY)} allowlisted "
          f"({sum(1 for t in BLUE_TOOL_REGISTRY.values() if t['read_only'])} read-only)")

    red.launch_scenario("operation_maya")
    env.advance_time(210)
    print(f"Simulation  : advanced to {clock(env.get_current_time())} — "
          f"{len(env.state.telemetry)} telemetry events")

    head("evidence")
    login = get_recent_logins(env, "arjun.rao")[0]
    print(f"  login     {clock(login['timestamp'])} {login['user_id']} from "
          f"{login['geo']['city']} ({login['source_ip']}) device_registered="
          f"{login['details']['device_registered']}")
    rogue = [s for s in get_active_sessions(env) if not s["device_managed"]]
    print(f"  session   {rogue[0]['session_id']} {rogue[0]['network_type']} "
          f"device={rogue[0]['device_id']}")
    device = [d for d in get_registered_devices(env, "arjun.rao") if not d["managed"]][0]
    print(f"  device    {device['device_id']} managed={device['managed']} "
          f"compliant={device['compliant']}")
    token = [t for t in get_oauth_activity(env, "arjun.rao")["tokens"]
             if not t["consent_prompt_shown"]][0]
    print(f"  token     {token['token_id']} consent={token['consent_prompt_shown']} "
          f"scopes={len(token['permissions'])}")
    rule = get_mailbox_rules(env, "arjun.rao")[0]
    print(f"  mail rule {rule['rule_id']} name={rule['name']!r} actions={rule['actions']}")
    drive = [d for d in get_cloud_drive_activity(env, "arjun.rao") if d["action"] == "download"]
    print(f"  drive     {len(drive)} confidential/restricted downloads")
    clone = [c for c in get_github_activity(env, "arjun.rao") if c["action"] == "repo.clone"][0]
    print(f"  github    {clone['details']['repository_count']} private repos cloned, "
          f"baseline {clone['details']['actor_30d_avg_repo_clones_per_day']}/day")
    data = get_data_access_activity(env, "customer-database")["access_events"]
    print(f"  data      {len(data)} access events against the customer store "
          "(the data stage has not run yet)")
    print("  hidden red truth reachable from Blue tools: "
          f"{'hidden' in env.get_state()}")

    head("containment, first action only")
    result = revoke_token(env, token["token_id"])
    print(f"  {result['action']} -> {result['success']} (impact {result['impact']})")
    show_verification("verify_environment:", verify_environment(env))
    print("  incomplete: the rogue session and device still hold the path.")

    head("red engine reacts")
    env.advance_time(60)
    status = red.get_attack_status()
    print(f"  branch {status['branch']}, status {status['status']}, "
          f"resilience {status['resilience_score']} — the revoked token forced the "
          "operation onto its session route.")

    head("further containment")
    for action in (
        lambda: remove_registered_device(env, device["device_id"]),
        lambda: remove_mailbox_rule(env, rule["rule_id"]),
        lambda: isolate_endpoint(env, "endpoint-arjun-01"),
        lambda: protect_data_asset(env, "customer-database"),
    ):
        result = action()
        print(f"  {result['action']:<26} -> {result['success']} (impact {result['impact']})")
    final = verify_environment(env)
    show_verification("verify_environment:", final)
    env.advance_time(120)
    final = verify_environment(env)
    print(f"  after more simulation time: attack {red.get_attack_status()['status']}, "
          f"contained {final['contained']}, risk {final['risk_score']}")

    head("reset")
    red.reset_attack()
    baseline = verify_environment(env)
    print(f"  posture {env.state.incident_status.status.value}   "
          f"resilience {env.state.safety.resilience_score}   "
          f"risk {baseline['risk_score']}   contained {baseline['contained']}")

    ok = (
        env.state.safety.resilience_score == 100
        and baseline["risk_score"] == 0
        and final["contained"]
    )
    print(f"\nPhase 2B result : {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
