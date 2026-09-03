"""Phase 3 demo: hand Trinetra a goal and let it run.

    cd backend && ./venv/bin/python run_agent_demo.py

Requires GEMINI_API_KEY (see .env.example). The tool sequence below is chosen by
the model at runtime — nothing in this file scripts the investigation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.agent import AgentConfigurationError, TrinetraAgent  # noqa: E402
from app.agent.models import AgentEvent, Phase  # noqa: E402
from app.simulator.environment import CyberEnvironment  # noqa: E402
from app.tools import IAM_FAULT  # noqa: E402

GOAL = (
    "Investigate the active security incident, contain confirmed threats, protect "
    "critical assets, and avoid unnecessary production disruption."
)

LABEL = {
    Phase.OBSERVE: "OBSERVE",
    Phase.DECIDE: "DECIDE",
    Phase.ACT: "ACT",
    Phase.EVALUATE: "EVALUATE",
    Phase.ADAPT: "ADAPT",
    Phase.RESULT: "RESULT",
    Phase.FAILED: "FAILED",
    Phase.FINAL: "FINAL",
}


def printer(event: AgentEvent) -> None:
    call = ""
    if event.tool:
        call = f"  {event.tool}({event.target or ''})"
    print(f"[{LABEL[event.phase]:<8}] step {event.step:02d}{call}")
    print(f"           {event.message}")


def main() -> int:
    env = CyberEnvironment("credential_compromise")
    env.reset()
    env.set_fault(IAM_FAULT)  # revoke_token('oauth-8492') will fail once attempted

    print("TRINETRA AGENT STARTED\n")
    print(f"GOAL\n{GOAL}\n")

    try:
        agent = TrinetraAgent(env, on_event=printer)
    except AgentConfigurationError as exc:
        print(f"CONFIGURATION ERROR\n{exc}")
        return 2

    state = agent.run(GOAL)
    v = state.latest_verification or {}

    print("\nFINAL STATUS")
    print(f"  {state.status.value}")
    print(f"  Risk Score   : {v.get('risk_score', 'n/a')}")
    print(f"  Contained    : {v.get('contained', 'n/a')}")
    print(f"  Steps        : {state.step}")
    print(f"  Tools called : {len(state.tools_called)}")
    print(f"  Actions      : {[a['tool'] + ':' + a['target'] for a in state.actions_taken]}")
    print(f"  Failures     : {[f['tool'] + ':' + f['error'] for f in state.failed_actions]}")
    print(f"  Adaptations  : {len(state.adaptations)}")
    if state.summary:
        print(f"\nSUMMARY\n  {state.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
