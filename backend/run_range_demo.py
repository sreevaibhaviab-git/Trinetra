"""Phase 1B demo: the Nexora cyber range — baseline, clock, safety governor.

Run from the `backend/` directory:

    python3 run_range_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.simulator.environment import CyberEnvironment, SimulationHalted  # noqa: E402

LINE = "=" * 62


def clock(timestamp: str) -> str:
    """Strip date and offset from an ISO timestamp for compact printing."""
    return timestamp[11:19]


def print_overview(env: CyberEnvironment) -> None:
    state = env.state
    print(LINE)
    print("TRINETRA CYBER RANGE")
    print(LINE)
    print(f"Environment     : {state.scenario}")
    print(f"Status          : {state.incident_status.status.value}")
    print(f"Resilience      : {state.safety.resilience_score}")
    print(f"Users           : {len(state.users)}")
    print(f"Endpoints       : {len(state.endpoints)}")
    print(f"Assets          : {len(state.assets)}")
    print(f"Telemetry       : {len(state.telemetry)} events")
    print(f"Simulation Time : {clock(env.get_current_time())}")
    print(f"Queue           : {len(state.clock.scheduled_events)} pending")


def main() -> int:
    env = CyberEnvironment("nexora_baseline")
    print_overview(env)

    baseline_time = env.get_current_time()
    baseline_queue = len(env.state.clock.scheduled_events)

    print("\n-- advance_time(60) " + "-" * 42)
    for event in env.advance_time(60):
        print(f"  processed {event.event_id}  {clock(event.scheduled_at)}  {event.name}")
    print(f"  Simulation Time : {clock(env.get_current_time())}")
    print(f"  Telemetry       : {len(env.state.telemetry)} events")

    print("\n-- safety governor " + "-" * 43)
    print(f"  pause()           -> {env.safety.pause().value}")
    print(f"  advance_time(60)  -> {len(env.advance_time(60))} events (time frozen)")
    print(f"  resume()          -> {env.safety.resume().value}")
    stop = env.safety.emergency_stop("manual test")
    print(f"  emergency_stop()  -> {stop['status']} ({stop['reason']})")
    print(f"    telemetry preserved : {stop['telemetry_preserved']} events")
    try:
        env.advance_time(60)
        print("    further mutations   : ALLOWED (unexpected)")
    except SimulationHalted:
        print("    further mutations   : refused")
    print(f"  restore_baseline()-> {env.safety.restore_baseline().value}")

    state = env.state
    restored = (
        state.incident_status.status.value == "HEALTHY"
        and state.safety.resilience_score == 100
        and env.get_current_time() == baseline_time
        and len(state.clock.scheduled_events) == baseline_queue
    )
    print("\n-- restored state " + "-" * 44)
    print(f"  Status          : {state.incident_status.status.value}")
    print(f"  Resilience      : {state.safety.resilience_score}")
    print(f"  Simulation Time : {clock(env.get_current_time())}")
    print(f"  Queue           : {len(state.clock.scheduled_events)} pending")
    print(f"\nBaseline restored : {restored}")
    return 0 if restored else 1


if __name__ == "__main__":
    raise SystemExit(main())
