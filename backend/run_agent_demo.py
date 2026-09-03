"""Phase 3 demo: hand Trinetra a goal and let it defend the live range.

    cd backend && ./venv/bin/python run_agent_demo.py

Requires GEMINI_API_KEY (see .env.example). Nothing in this file scripts the
investigation: the goal below is the agent's only input, and every tool call and
containment decision comes from the model at runtime. The Red Engine keeps
running on the same simulation clock while the agent works.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.agent import AgentConfigurationError, TrinetraAgent  # noqa: E402
from app.agent.models import AgentEvent, Phase  # noqa: E402
from app.simulator.environment import CyberEnvironment  # noqa: E402
from app.simulator.red_engine import RedAttackEngine  # noqa: E402
from app.tools import verify_environment  # noqa: E402

GOAL = (
    "Keep Nexora operational. Investigate the active incident, contain confirmed "
    "threats, protect critical assets, and minimize unnecessary disruption."
)

# Simulated seconds of incident that have already elapsed when the agent is
# called in. Enough for observable evidence; the operation is far from finished.
WARMUP_SECONDS = 150


def printer(event: AgentEvent) -> None:
    call = f"  {event.tool}({event.target or ''})" if event.tool else ""
    print(f"\n[{event.phase.value}] step {event.step:02d}{call}")
    print(f"  {event.message}")


def main() -> int:
    env = CyberEnvironment("nexora_baseline")
    red = RedAttackEngine(env)
    red.launch_scenario("operation_maya")
    env.advance_time(WARMUP_SECONDS)

    print("TRINETRA AUTONOMOUS RESPONSE")
    print(f"\nGOAL\n  {GOAL}")
    print(
        f"\nRANGE\n  {env.scenario} at {env.get_current_time()[11:19]} — "
        f"{len(env.state.telemetry)} telemetry events, "
        f"resilience {env.state.safety.resilience_score}"
    )

    try:
        agent = TrinetraAgent(env, on_event=printer)
    except AgentConfigurationError as exc:
        print(f"\nCONFIGURATION ERROR\n  {exc}")
        return 2

    state = agent.run(GOAL)

    # Final word comes from the tools, not from the agent's own claim.
    verification = verify_environment(env)
    print("\n" + "=" * 68)
    print("FINAL")
    print(f"  Status      : {state.status.value}")
    print(f"  Contained   : {verification['contained']}")
    print(f"  Risk        : {verification['risk_score']}")
    print(f"  Resilience  : {verification['resilience_score']}")
    print(f"  Steps       : {state.step}")
    print(f"  Tools called: {len(state.tools_called)}")
    print(f"  Actions     : {len(state.actions_taken)} "
          f"{[a['tool'] + ':' + str(a['target']) for a in state.actions_taken]}")
    print(f"  Failed      : {len(state.failed_actions)} "
          f"{[f['tool'] + ':' + f['error'] for f in state.failed_actions]}")
    print(f"  Adaptations : {len(state.adaptations)}")
    print(f"  Simulation  : {env.get_current_time()[11:19]}, "
          f"attack {red.get_attack_status()['status']}")
    if state.final_outcome:
        print(f"\nOUTCOME\n  {state.final_outcome}")

    return 0 if verification["contained"] or state.status.value == "EMERGENCY_STOPPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
