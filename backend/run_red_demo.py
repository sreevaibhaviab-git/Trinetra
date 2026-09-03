"""Phase 2A demo: operation_maya unfolding across the Nexora cyber range.

Run from the `backend/` directory:

    python3 run_red_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.simulator.environment import CyberEnvironment  # noqa: E402
from app.simulator.red_engine import RedAttackEngine  # noqa: E402

LINE = "=" * 68


def clock(timestamp: str) -> str:
    return timestamp[11:19]


def advance(env: CyberEnvironment, seconds: int) -> None:
    """Move the range forward and print the evidence it produced."""
    before = len(env.state.telemetry)
    env.advance_time(seconds)
    for event in env.state.telemetry[before:]:
        print(
            f"  {clock(event.timestamp)}  {event.source.value:<9}"
            f"{event.message.split('.')[0]}."
        )
    print(f"    -> Resilience: {env.state.safety.resilience_score}"
          f"   Posture: {env.state.incident_status.status.value}")


def main() -> int:
    env = CyberEnvironment("nexora_baseline")
    red = RedAttackEngine(env)

    print(LINE)
    print("TRINETRA CYBER RANGE — RED ENGINE")
    print(LINE)
    print(f"Environment : {env.scenario}")
    print(f"Posture     : {env.state.incident_status.status.value}")
    print(f"Resilience  : {env.state.safety.resilience_score}")
    print(f"Time        : {clock(env.get_current_time())}")

    red.launch_scenario("operation_maya")
    print(f"\nLaunched    : operation_maya ({len(red.get_attack_status()['pending_stages'])} stages queued)")

    print("\n-- identity foothold " + "-" * 46)
    advance(env, 80)

    print("\n-- SaaS discovery and persistence " + "-" * 33)
    advance(env, 100)

    print("\n-- paused " + "-" * 57)
    print(f"  pause() -> {env.safety.pause().value}")
    advance(env, 120)
    print(f"  time still {clock(env.get_current_time())}, "
          f"stages pending: {len(red.get_attack_status()['pending_stages'])}")
    print(f"  resume() -> {env.safety.resume().value}")

    print("\n-- developer, cloud and data " + "-" * 38)
    advance(env, 150)
    advance(env, 90)

    status = red.get_attack_status()
    print("\n-- final " + "-" * 58)
    print(f"  Attack status   : {status['status']}")
    print(f"  Stages complete : {len(status['completed_stages'])}/11 ({status['branch']} branch)")
    print(f"  Simulation      : {status['simulation_status']}")
    print(f"  Resilience      : {status['resilience_score']}")
    print(f"  Posture         : {env.state.incident_status.status.value}")
    print(f"  Telemetry       : {status['telemetry_events']} events preserved")
    leaked = [k for k in env.get_state() if k == "hidden"]
    print(f"  Hidden truth in observable state : {bool(leaked)}")

    red.reset_attack()
    print("\n-- restored " + "-" * 55)
    print(f"  Posture     : {env.state.incident_status.status.value}")
    print(f"  Resilience  : {env.state.safety.resilience_score}")
    print(f"  Time        : {clock(env.get_current_time())}")
    print(f"  Attack      : {red.get_attack_status()['status']}")

    restored = (
        env.state.incident_status.status.value == "HEALTHY"
        and env.state.safety.resilience_score == 100
        and not leaked
    )
    print(f"\nBaseline restored : {restored}")
    return 0 if restored else 1


if __name__ == "__main__":
    raise SystemExit(main())
