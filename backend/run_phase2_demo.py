"""Phase 2 demo: investigate, respond, verify, reset.

    cd backend && python3 run_phase2_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.simulator.environment import CyberEnvironment  # noqa: E402
from app.tools import (  # noqa: E402
    IAM_FAULT,
    block_ip,
    disable_user,
    get_active_sessions,
    get_environment_summary,
    get_recent_logins,
    get_tokens,
    revoke_token,
    terminate_session,
    verify_environment,
)

W = 74


def head(title: str) -> None:
    print(f"\n{'=' * W}\n{title}\n{'=' * W}")


def show(result: Dict[str, Any]) -> None:
    print(f"  -> {result}")


def report(v: Dict[str, Any]) -> None:
    print(f"  contained                 : {v['contained']}")
    print(f"  risk_score                : {v['risk_score']}/100")
    print(f"  status                    : {v['status']}")
    print(f"  suspicious_sessions       : {v['suspicious_sessions']}")
    print(f"  active_compromised_tokens : {v['active_compromised_tokens']}")
    print(f"  exposed_critical_assets   : {v['exposed_critical_assets']}")
    print(f"  unblocked_hostile_ips     : {v['unblocked_hostile_ips']}")
    print(f"  remaining_threats         : {len(v['remaining_threats'])}")
    for t in v["remaining_threats"]:
        print(f"     - {t['type']:<22} {t['target']:<18} {t['detail']}")


def main() -> int:
    # 1. load scenario
    env = CyberEnvironment("credential_compromise")
    head("1. SCENARIO LOADED")
    s = get_environment_summary(env)
    print(f"  {s['organization']} / {s['scenario']} / {s['status']}")
    print(f"  sessions={s['active_sessions']} tokens={s['active_tokens']} alerts={s['open_alerts']}")

    # 2. inspect Arjun
    head("2. INVESTIGATE — arjun.rao")
    for login in get_recent_logins(env, "arjun.rao"):
        print(f"  {login['timestamp']}  {login['geo']['city']:<10} {login['source_ip']:<16} "
              f"device_managed={login['details']['device_registered']}")
    for sess in get_active_sessions(env, "arjun.rao"):
        print(f"  {sess['session_id']}  {sess['geo']['city']:<10} {sess['network_type']:<18} "
              f"managed={sess['device_managed']}  {sess['status']}")

    # 3. inspect the token
    head("3. INVESTIGATE — oauth-8492")
    token = next(t for t in get_tokens(env, "arjun.rao") if t["token_id"] == "oauth-8492")
    print(f"  issued {token['issued_at']} from {token['issued_from_ip']} via {token['issued_via_session']}")
    print(f"  permissions={token['permissions']} consent_prompt_shown={token['consent_prompt_shown']}")

    head("4. BASELINE VERIFICATION")
    baseline = verify_environment(env)
    report(baseline)

    # 4. revoke — first under the injected IAM fault, then for real
    head("5. RESPOND — revoke_token (deterministic fault, then retry)")
    env.set_fault(IAM_FAULT)
    show(revoke_token(env, "oauth-8492"))
    env.set_fault(IAM_FAULT, False)
    show(revoke_token(env, "oauth-8492"))

    # 5. terminate the suspicious session
    head("6. RESPOND — terminate suspicious session")
    suspicious = baseline["suspicious_sessions"]
    for session_id in suspicious:
        show(terminate_session(env, session_id))
    show(block_ip(env, "185.220.101.47"))

    # 6. disable the principal only if it is still a listed threat
    head("7. RESPOND — disable principal if required")
    interim = verify_environment(env)
    exposed = [t["target"] for t in interim["remaining_threats"] if t["type"] == "EXPOSED_CREDENTIALS"]
    if exposed:
        for user_id in exposed:
            show(disable_user(env, user_id))
    else:
        print("  -> not required")

    # 7/8. verify and compare
    head("8. POST-CONTAINMENT VERIFICATION")
    final = verify_environment(env)
    report(final)
    print(f"\n  risk {baseline['risk_score']} -> {final['risk_score']}   "
          f"status {baseline['status']} -> {final['status']}")
    print(f"  containment_actions: {final['containment_actions']}")

    # 9. reset
    head("9. RESET")
    env.reset()
    after = verify_environment(env)
    restored = (
        after["risk_score"] == baseline["risk_score"]
        and after["suspicious_sessions"] == baseline["suspicious_sessions"]
        and after["active_compromised_tokens"] == baseline["active_compromised_tokens"]
        and not get_environment_summary(env)["containment_actions"]
    )
    print(f"  risk_score after reset    : {after['risk_score']}/100")
    print(f"  baseline restored         : {restored}")

    ok = (
        baseline["contained"] is False
        and final["contained"] is True
        and final["risk_score"] < baseline["risk_score"]
        and restored
    )
    head("DEMO RESULT")
    print("  PASS — investigation, response, verification and reset all behave." if ok
          else "  FAIL — see output above.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
