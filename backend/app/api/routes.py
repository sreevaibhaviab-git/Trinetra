"""HTTP surface over the existing range.

Routes are deliberately thin: they translate a request into a call on the
objects that already own the behaviour — `CyberEnvironment`, `SafetyGovernor`,
`RedAttackEngine`, the Blue tool allowlist and `TrinetraAgent` — and turn their
return values into JSON. No incident logic lives here.

Two invariants hold everywhere in this module: nothing bypasses the safety
governor, and nothing serialises `state.hidden` or the Red Engine's own view of
its progress.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.agent.controller import AgentConfigurationError, TrinetraAgent
from app.agent.models import AgentEvent, AgentState
from app.agent.tool_registry import call_tool
from app.api.modes import (
    OperationMode,
    Recommendation,
    RecommendationStatus,
    TrainingSession,
    score_training,
)
from app.api.schemas import (
    AdvanceRequest,
    AgentRunRequest,
    CopilotRunRequest,
    EmergencyStopRequest,
    LaunchRequest,
    ModeRequest,
    ToolCallRequest,
)
from app.models.environment import SimulationStatus
from app.simulator.environment import CyberEnvironment, SimulationHalted
from app.simulator.red_engine import FLAGSHIP_SCENARIO, RedAttackEngine
from app.tools import (
    BLUE_TOOL_REGISTRY,
    get_environment_summary,
    get_timeline,
    verify_environment,
)

BASELINE = "nexora_baseline"
TELEMETRY_PAGE = 40

router = APIRouter()


class RangeSession:
    """The single in-memory range this process owns."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.env = CyberEnvironment(BASELINE)
        self.red = RedAttackEngine(self.env)
        self.agent_state: Optional[AgentState] = None
        self.agent_running = False
        self.mode = getattr(self, "mode", OperationMode.AUTONOMOUS)
        self.recommendations: List[Recommendation] = []
        self.training: Optional[TrainingSession] = None

    # The governor is the environment's own; never re-implemented here.
    @property
    def safety(self):
        return self.env.safety

    def emergency_stopped(self) -> bool:
        return (
            self.env.state.safety.mutations_locked
            or self.env.state.safety.simulation_status is SimulationStatus.EMERGENCY_STOPPED
        )


session = RangeSession()


# ── helpers ──────────────────────────────────────────────────────────


def _attack_view() -> Dict[str, Any]:
    """Operator-safe attack status: lifecycle only, never the adversary's plan."""
    status = session.red.get_attack_status()
    return {
        "status": status["status"],
        "scenario": status["scenario"],
        "simulation_status": status["simulation_status"],
        "resilience_score": status["resilience_score"],
        "telemetry_events": status["telemetry_events"],
        "pending_events": len(status["pending_stages"]),
    }


def _agent_view() -> Dict[str, Any]:
    state = session.agent_state
    if state is None:
        return {
            "status": "IDLE",
            "running": session.agent_running,
            "current_phase": None,
            "current_action": None,
            "steps": 0,
            "adaptations": 0,
            "events": [],
        }
    last_action = state.actions_taken[-1] if state.actions_taken else None
    return {
        "status": state.status.value,
        "running": session.agent_running,
        "current_phase": state.phase.value,
        "current_action": f"{last_action['tool']}:{last_action['target']}" if last_action else None,
        "steps": state.step,
        "adaptations": len(state.adaptations),
        "events": [e.to_dict() for e in state.events],
    }


def _pending_recommendation() -> Optional[Recommendation]:
    return next(
        (r for r in reversed(session.recommendations)
         if r.status is RecommendationStatus.PENDING),
        None,
    )


def _training_summary() -> Optional[Dict[str, Any]]:
    """Dashboard-sized view of a training run: counts, not the whole action log."""
    if session.training is None:
        return None
    view = session.training.to_dict(session.env.get_current_time())
    view.pop("actions", None)
    return view


def _guard_mode(*allowed: OperationMode) -> None:
    if session.mode not in allowed:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Not available in {session.mode.value} mode; "
                f"switch to {' or '.join(m.value for m in allowed)}."
            ),
        )


def _guard_running() -> None:
    if session.agent_running:
        raise HTTPException(status_code=409, detail="An agent run is already in progress.")


def _guard_halted(action: str) -> None:
    if session.emergency_stopped():
        raise HTTPException(
            status_code=409,
            detail=f"Simulation is emergency-stopped; {action} is refused until baseline restore.",
        )


# ── health and range ─────────────────────────────────────────────────


@router.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "scenario": session.env.scenario,
        "simulation_time": session.env.get_current_time(),
        "simulation_status": session.env.state.safety.simulation_status.value,
    }


@router.get("/range/state")
def range_state() -> Dict[str, Any]:
    """The observable estate. `hidden` is dropped by the state serialiser itself."""
    return session.env.get_state()


@router.post("/range/initialize")
def range_initialize() -> Dict[str, Any]:
    session.reset()
    return {"initialized": True, "summary": get_environment_summary(session.env)}


@router.post("/range/reset")
def range_reset() -> Dict[str, Any]:
    session.red.reset_attack()
    session.agent_state = None
    return {"reset": True, "summary": get_environment_summary(session.env)}


@router.post("/range/advance")
def range_advance(body: AdvanceRequest) -> Dict[str, Any]:
    _guard_halted("advancing time")
    try:
        fired = session.env.advance_time(body.seconds)
    except SimulationHalted as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "simulation_time": session.env.get_current_time(),
        "events_processed": len(fired),
        "paused": session.env.state.safety.simulation_status is SimulationStatus.PAUSED,
        "resilience_score": session.env.state.safety.resilience_score,
    }


@router.get("/range/telemetry")
def range_telemetry(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = Query(default=60, ge=1, le=500),
) -> List[Dict[str, Any]]:
    events = get_timeline(session.env, since=since, category=category, limit=limit)
    if severity:
        events = [e for e in events if e["severity"] == severity.lower()]
    return events


# ── attack ───────────────────────────────────────────────────────────


@router.post("/attack/launch")
def attack_launch(body: LaunchRequest) -> Dict[str, Any]:
    _guard_halted("launching a scenario")
    try:
        session.red.launch_scenario(body.scenario)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:  # governor refused
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"launched": body.scenario, "attack": _attack_view()}


@router.get("/attack/status")
def attack_status() -> Dict[str, Any]:
    return _attack_view()


@router.post("/attack/stop")
def attack_stop() -> Dict[str, Any]:
    result = session.red.stop_attack()
    return {"stopped": True, "cancelled_events": len(result["cancelled_events"]),
            "attack": _attack_view()}


# ── safety governor ──────────────────────────────────────────────────


@router.post("/simulation/pause")
def simulation_pause() -> Dict[str, Any]:
    return {"simulation_status": session.safety.pause().value}


@router.post("/simulation/resume")
def simulation_resume() -> Dict[str, Any]:
    if session.emergency_stopped():
        raise HTTPException(
            status_code=409,
            detail="Emergency stop can only be cleared by restoring the baseline.",
        )
    return {"simulation_status": session.safety.resume().value}


@router.post("/simulation/emergency-stop")
def simulation_emergency_stop(body: EmergencyStopRequest) -> Dict[str, Any]:
    return session.safety.emergency_stop(body.reason)


@router.post("/simulation/restore-baseline")
def simulation_restore_baseline() -> Dict[str, Any]:
    session.red.reset_attack()
    session.agent_state = None
    return {
        "simulation_status": session.env.state.safety.simulation_status.value,
        "summary": get_environment_summary(session.env),
    }


# ── blue tools ───────────────────────────────────────────────────────


@router.get("/blue/tools")
def blue_tools() -> List[Dict[str, Any]]:
    return [
        {
            "name": entry["name"],
            "description": entry["description"],
            "category": entry["category"],
            "read_only": entry["read_only"],
            "impact": entry["impact"],
        }
        for entry in BLUE_TOOL_REGISTRY.values()
    ]


@router.post("/blue/tools/{tool_name}")
def blue_tool_call(tool_name: str, body: ToolCallRequest) -> Dict[str, Any]:
    entry = BLUE_TOOL_REGISTRY.get(tool_name)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"{tool_name} is not an allowlisted Blue tool.")
    if not entry["read_only"]:
        _guard_halted(f"{tool_name}")
        # Only a human working in TRAINING drives defensive tools by hand; in
        # COPILOT they go through approval, in AUTONOMOUS through the agent.
        _guard_mode(OperationMode.TRAINING)

    outcome = call_tool(session.env, tool_name, body.arguments)
    if session.training is not None and session.training.active:
        result = outcome.get("result")
        session.training.record(
            {
                "timestamp": session.env.get_current_time(),
                "tool": tool_name,
                "arguments": dict(body.arguments),
                "read_only": entry["read_only"],
                "impact": entry["impact"],
                "success": bool(outcome.get("success"))
                and not (isinstance(result, dict) and result.get("success") is False),
            }
        )
    if not outcome.get("success"):
        raise HTTPException(
            status_code=400,
            detail=f"{outcome.get('error', 'TOOL_ERROR')}: {outcome.get('detail', '')}".strip(": "),
        )
    # A defensive tool reports its own refusal inside the payload (unknown target,
    # already contained, governor lock); surface that as an HTTP error too.
    result = outcome["result"]
    if isinstance(result, dict) and result.get("success") is False:
        error = str(result.get("error", "ACTION_FAILED"))
        status = 409 if error == "SIMULATION_EMERGENCY_STOPPED" else 400
        raise HTTPException(status_code=status, detail=f"{error}: {result.get('message', '')}")
    return {"tool": tool_name, "impact": entry["impact"], "result": result}


# ── agent ────────────────────────────────────────────────────────────


@router.post("/agent/run")
def agent_run(body: AgentRunRequest) -> Dict[str, Any]:
    _guard_mode(OperationMode.AUTONOMOUS)
    _guard_running()
    _guard_halted("running the agent")

    events: List[AgentEvent] = []
    try:
        agent = TrinetraAgent(session.env, on_event=events.append)
    except AgentConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    session.agent_running = True
    try:
        state = agent.run(body.goal)
    except Exception as exc:  # never leak a traceback to the UI
        raise HTTPException(status_code=500, detail=f"Agent run failed: {exc}") from exc
    finally:
        session.agent_running = False

    session.agent_state = state
    verification = state.latest_verification or verify_environment(session.env)
    return {
        "status": state.status.value,
        "contained": verification["contained"],
        "risk_score": verification["risk_score"],
        "resilience_score": verification["resilience_score"],
        "steps": state.step,
        "actions": state.actions_taken,
        "failed_actions": state.failed_actions,
        "adaptations": len(state.adaptations),
        "adaptation_notes": state.adaptations,
        "events": [e.to_dict() for e in state.events],
        "outcome": state.final_outcome,
    }


@router.get("/agent/status")
def agent_status() -> Dict[str, Any]:
    view = _agent_view()
    view.pop("events", None)
    return view


@router.get("/agent/events")
def agent_events() -> List[Dict[str, Any]]:
    return _agent_view()["events"]


# ── modes ────────────────────────────────────────────────────────────


@router.get("/mode")
def get_mode() -> Dict[str, Any]:
    return {
        "mode": session.mode.value,
        "available": [m.value for m in OperationMode],
        "pending_recommendation": (
            _pending_recommendation().to_dict() if _pending_recommendation() else None
        ),
        "training_active": bool(session.training and session.training.active),
    }


@router.post("/mode")
def set_mode(body: ModeRequest) -> Dict[str, Any]:
    """Switch who may act. The range itself is left exactly as it stands."""
    try:
        session.mode = OperationMode(body.mode.upper())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown mode {body.mode!r}. Available: "
            + ", ".join(m.value for m in OperationMode),
        ) from exc
    return get_mode()


# ── copilot ──────────────────────────────────────────────────────────


@router.post("/copilot/run")
def copilot_run(body: CopilotRunRequest) -> Dict[str, Any]:
    """Investigate read-only and propose one action. Nothing is executed here."""
    _guard_mode(OperationMode.COPILOT)
    _guard_running()
    _guard_halted("running the copilot")

    proposed: List[Recommendation] = []

    def gate(tool_name: str, arguments: Dict[str, Any], reason: str) -> Optional[str]:
        entry = BLUE_TOOL_REGISTRY.get(tool_name)
        if entry is None or entry["read_only"]:
            return None
        if not proposed:
            proposed.append(
                Recommendation(
                    tool_name=tool_name,
                    arguments=dict(arguments),
                    impact=entry["impact"],
                    reason=reason or entry["description"],
                    proposed_at=session.env.get_current_time(),
                )
            )
        return (
            "Copilot mode: this action needs human approval. Explain your reasoning "
            "and stop; the operator will approve or reject it."
        )

    events: List[AgentEvent] = []
    try:
        agent = TrinetraAgent(session.env, on_event=events.append, action_gate=gate)
    except AgentConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    session.agent_running = True
    try:
        state = agent.run(body.goal)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Copilot run failed: {exc}") from exc
    finally:
        session.agent_running = False

    session.agent_state = state
    for stale in session.recommendations:
        if stale.status is RecommendationStatus.PENDING:
            stale.status = RecommendationStatus.EXPIRED
    session.recommendations.extend(proposed)
    return {
        "status": state.status.value,
        "steps": state.step,
        "recommendation": proposed[0].to_dict() if proposed else None,
        "rationale": state.summary,
        "events": [e.to_dict() for e in state.events],
        "verification": state.latest_verification or verify_environment(session.env),
    }


@router.get("/copilot/recommendation")
def copilot_recommendation() -> Dict[str, Any]:
    pending = _pending_recommendation()
    return {
        "pending": pending.to_dict() if pending else None,
        "history": [r.to_dict() for r in session.recommendations],
    }


def _find_recommendation(recommendation_id: str) -> Recommendation:
    found = next((r for r in session.recommendations if r.id == recommendation_id), None)
    if found is None:
        raise HTTPException(status_code=404, detail=f"No recommendation {recommendation_id}.")
    if found.status is not RecommendationStatus.PENDING:
        raise HTTPException(
            status_code=409, detail=f"Recommendation is already {found.status.value}."
        )
    return found


@router.post("/copilot/recommendation/{recommendation_id}/approve")
def copilot_approve(recommendation_id: str) -> Dict[str, Any]:
    _guard_mode(OperationMode.COPILOT)
    found = _find_recommendation(recommendation_id)
    _guard_halted(found.tool_name)

    outcome = call_tool(session.env, found.tool_name, found.arguments)
    result = outcome.get("result")
    succeeded = bool(outcome.get("success")) and not (
        isinstance(result, dict) and result.get("success") is False
    )
    found.status = RecommendationStatus.EXECUTED if succeeded else RecommendationStatus.APPROVED
    found.result = result if isinstance(result, dict) else outcome
    return {
        "recommendation": found.to_dict(),
        "executed": succeeded,
        "verification": verify_environment(session.env),
    }


@router.post("/copilot/recommendation/{recommendation_id}/reject")
def copilot_reject(recommendation_id: str) -> Dict[str, Any]:
    _guard_mode(OperationMode.COPILOT)
    found = _find_recommendation(recommendation_id)
    found.status = RecommendationStatus.REJECTED
    return {
        "recommendation": found.to_dict(),
        "executed": False,
        "verification": verify_environment(session.env),
    }


# ── training ─────────────────────────────────────────────────────────


@router.post("/training/start")
def training_start() -> Dict[str, Any]:
    _guard_mode(OperationMode.TRAINING)
    verification = verify_environment(session.env)
    session.training = TrainingSession(
        started_at=session.env.get_current_time(),
        starting_risk=verification["risk_score"],
        starting_resilience=session.env.state.safety.resilience_score,
    )
    return session.training.to_dict(session.env.get_current_time())


@router.get("/training/status")
def training_status() -> Dict[str, Any]:
    if session.training is None:
        raise HTTPException(status_code=404, detail="No training session has been started.")
    return session.training.to_dict(session.env.get_current_time())


@router.post("/training/finish")
def training_finish() -> Dict[str, Any]:
    if session.training is None or not session.training.active:
        raise HTTPException(status_code=409, detail="No training session is active.")
    verification = verify_environment(session.env)
    session.training.debrief = score_training(
        session.training, verification, session.env.state.safety.resilience_score
    )
    session.training.active = False
    return session.training.to_dict(session.env.get_current_time())


# ── one-shot dashboard ───────────────────────────────────────────────


@router.get("/dashboard")
def dashboard() -> Dict[str, Any]:
    env = session.env
    state = env.state
    verification = verify_environment(env)
    agent = _agent_view()
    pending = _pending_recommendation()
    return {
        "mode": session.mode.value,
        "copilot": {
            "pending_recommendation": pending.to_dict() if pending else None,
            "history": len(session.recommendations),
        },
        "training": _training_summary(),
        "environment": {
            "scenario": env.scenario,
            "status": state.incident_status.status.value,
            "simulation_time": env.get_current_time(),
            "resilience_score": state.safety.resilience_score,
            "risk_score": verification["risk_score"],
        },
        "attack": _attack_view(),
        "incident": {
            "contained": verification["contained"],
            "remaining_threats": verification["remaining_threats"],
            "identity_risk": verification["identity_risk"],
            "endpoint_risk": verification["endpoint_risk"],
            "saas_risk": verification["saas_risk"],
            "cloud_risk": verification["cloud_risk"],
            "data_risk": verification["data_risk"],
        },
        "assets": [
            {
                "asset_id": asset.asset_id,
                "name": asset.name,
                "criticality": asset.criticality.value,
                "status": asset.status,
                "restricted": asset.restricted,
                "exposed": asset.exposed,
            }
            for asset in state.assets.values()
        ],
        "endpoints": [
            {
                "endpoint_id": e.endpoint_id,
                "hostname": e.hostname,
                "owner": e.owner,
                "status": e.status,
                "isolated": e.isolated,
            }
            for e in state.endpoints.values()
        ],
        "telemetry": get_timeline(env, limit=TELEMETRY_PAGE)[-TELEMETRY_PAGE:],
        "agent": agent,
        "safety": {
            "simulation_status": state.safety.simulation_status.value,
            "emergency_stopped": session.emergency_stopped(),
            "emergency_stop_reason": state.safety.emergency_stop_reason,
            "critical_failure_threshold": state.safety.critical_failure_threshold,
        },
    }
