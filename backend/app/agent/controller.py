"""TrinetraAgent — the autonomous loop around the Phase 2 tools.

The controller owns safety and bookkeeping only: allowlisting, argument
validation, the step ceiling and the rule that containment cannot be declared
without a fresh verification. Which tools to call, in what order, and what to do
about a failure are decided entirely by the model.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.agent.models import AgentEvent, AgentState, AgentStatus, Phase
from app.models.environment import SimulationStatus
from app.agent.prompts import SYSTEM_INSTRUCTION
from app.agent.tool_registry import REGISTRY, call_tool, function_declarations, target_of
from app.simulator.environment import CyberEnvironment, SimulationHalted

MAX_STEPS = 14
MAX_NUDGES = 2
MAX_API_FAILURES = 2
# One retry per model request, and a hard ceiling on how much the agent can ask
# for in a single turn — a wide fan-out of overlapping reads is what makes the
# loop feel stalled.
MODEL_RETRIES = 1
MAX_TOOL_CALLS_PER_TURN = 4
REQUEST_TIMEOUT_MS = 60_000
# Simulated seconds the world moves on between agent iterations. The Red Engine
# rides the same clock, so the incident keeps developing while Trinetra works.
TICK_SECONDS = 25
DEFAULT_MODEL = "gemini-2.5-flash"

EventSink = Callable[[AgentEvent], None]


class AgentConfigurationError(RuntimeError):
    """Raised when the agent cannot be constructed (missing key, missing SDK)."""


def _load_env() -> None:
    """Read backend/.env if python-dotenv is available. Credentials never live in code."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # optional convenience only
        return
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    load_dotenv()


def _load_api_key(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    _load_env()
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise AgentConfigurationError(
            "GEMINI_API_KEY is not set. Copy .env.example to .env and add your key, "
            "or export GEMINI_API_KEY before running."
        )
    return key


def _shorten(text: str, limit: int = 260) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


class TrinetraAgent:
    def __init__(
        self,
        env: CyberEnvironment,
        *,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_steps: int = MAX_STEPS,
        client: Any = None,
        on_event: Optional[EventSink] = None,
    ) -> None:
        self.env = env
        _load_env()
        self.model = model or os.environ.get("GEMINI_MODEL", "").strip() or DEFAULT_MODEL
        self.max_steps = max_steps
        self.on_event = on_event

        if client is not None:
            self.client = client
        else:
            try:
                from google import genai
            except ImportError as exc:  # pragma: no cover - install-time problem
                raise AgentConfigurationError(
                    "google-genai is not installed. Run: pip install -r requirements.txt"
                ) from exc
            self.client = genai.Client(api_key=_load_api_key(api_key))

    # ── event helpers ────────────────────────────────────────────
    def _emit(self, state: AgentState, phase: Phase, message: str, **kw: Any) -> None:
        event = AgentEvent(step=state.step, phase=phase, message=message, **kw)
        state.phase = phase
        state.events.append(event)
        if self.on_event:
            self.on_event(event)

    # ── world clock and safety governor ──────────────────────────
    def _halted(self) -> bool:
        """True once the SafetyGovernor has locked the range. Never overridden."""
        safety = self.env.state.safety
        return (
            safety.mutations_locked
            or safety.simulation_status is SimulationStatus.EMERGENCY_STOPPED
        )

    def _advance_world(self, state: AgentState) -> None:
        """Let the incident develop between iterations on the existing clock."""
        if self._halted():
            return
        try:
            self.env.advance_time(TICK_SECONDS)
        except SimulationHalted:
            return

    # ── model call ───────────────────────────────────────────────
    def _config(self) -> Any:
        from google.genai import types

        return types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=[types.Tool(function_declarations=function_declarations())],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            temperature=0.2,
            http_options=types.HttpOptions(timeout=REQUEST_TIMEOUT_MS),
        )

    def _generate(self, contents: List[Any]) -> Any:
        """One model request, retried at most once. A hung call cannot block forever."""
        last: Exception
        for attempt in range(MODEL_RETRIES + 1):
            print("Waiting for Gemini decision...", flush=True)
            try:
                return self.client.models.generate_content(
                    model=self.model, contents=contents, config=self._config()
                )
            except Exception as exc:  # timeout, transport error, transient 5xx
                last = exc
                if attempt >= MODEL_RETRIES:
                    break
        raise last

    def run(self, goal: str) -> AgentState:
        from google.genai import types

        state = AgentState(goal=goal)
        contents: List[Any] = [
            types.Content(
                role="user",
                parts=[
                    types.Part(
                        text=(
                            f"OPERATOR GOAL: {goal}\n"
                            f"SIMULATION CLOCK: {self.env.get_current_time()} "
                            "(the range's own clock — the only time reference that exists)"
                        )
                    )
                ],
            )
        ]
        nudges = 0
        api_failures = 0
        pending_adaptation = False
        verified_since_action = True

        while state.step < self.max_steps:
            state.step += 1

            if self._halted():
                state.status = AgentStatus.EMERGENCY_STOPPED
                state.final_outcome = (
                    "SafetyGovernor emergency-stopped the range; no further changes attempted."
                )
                self._emit(state, Phase.FINAL, state.final_outcome)
                return state

            try:
                response = self._generate(contents)
            except Exception as exc:
                api_failures += 1
                self._emit(state, Phase.FAILED, f"Gemini API error: {_shorten(str(exc), 180)}")
                if api_failures >= MAX_API_FAILURES:
                    state.status = AgentStatus.ERROR
                    state.final_outcome = "Gemini was unreachable; handing back to a human."
                    self._emit(state, Phase.FINAL, state.final_outcome)
                    return state
                continue
            api_failures = 0

            candidate = (response.candidates or [None])[0]
            parts = list(getattr(getattr(candidate, "content", None), "parts", None) or [])
            contents.append(
                candidate.content
                if candidate is not None and candidate.content is not None
                else types.Content(role="model", parts=[])
            )

            rationale = " ".join(p.text.strip() for p in parts if getattr(p, "text", None))
            calls = [p.function_call for p in parts if getattr(p, "function_call", None)]
            # Keep each turn tight: anything past the cap is refused, not run.
            dropped = calls[MAX_TOOL_CALLS_PER_TURN:]
            calls = calls[:MAX_TOOL_CALLS_PER_TURN]

            if rationale:
                phase = Phase.ADAPT if pending_adaptation else Phase.DECIDE
                if pending_adaptation:
                    state.adaptations.append(_shorten(rationale, 180))
                self._emit(state, phase, _shorten(rationale))
            pending_adaptation = False

            # ── model is finished ────────────────────────────────
            if not calls:
                needs_check = not verified_since_action or state.latest_verification is None
                if needs_check and nudges < MAX_NUDGES:
                    nudges += 1
                    contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part(
                                    text=(
                                        "Containment cannot be accepted without a fresh "
                                        "verify_environment result reflecting your latest actions. "
                                        "Verify now, and continue working if threats remain."
                                    )
                                )
                            ],
                        )
                    )
                    continue
                state.summary = _shorten(rationale, 600) or "Agent finished without a summary."
                break

            # ── execute the requested tools ──────────────────────
            response_parts = []
            for call in calls:
                name = call.name or ""
                args: Dict[str, Any] = dict(call.args or {})
                spec = REGISTRY.get(name)
                kind = spec.kind if spec else "unknown"
                target = target_of(name, args)

                if kind == "defensive":
                    state.status = AgentStatus.CONTAINING
                    self._emit(
                        state,
                        Phase.ACT,
                        f"Executing {name}"
                        + (f" on {target}" if target else "")
                        + ".",
                        tool=name,
                        target=target or None,
                    )
                elif kind == "verification":
                    state.status = AgentStatus.VERIFYING
                    self._emit(state, Phase.EVALUATE, "Verifying environment state.", tool=name)
                else:
                    self._emit(
                        state,
                        Phase.OBSERVE,
                        f"Inspecting {name.replace('get_', '').replace('_', ' ')}"
                        + (f" for {target}" if target else "")
                        + ".",
                        tool=name,
                        target=target or None,
                    )

                outcome = call_tool(self.env, name, args)
                state.tools_called.append(name)
                payload = outcome.get("result", outcome)
                ok = bool(outcome.get("success")) and not (
                    isinstance(payload, dict) and payload.get("success") is False
                )

                if kind == "defensive":
                    record = {"tool": name, "target": target, "step": state.step}
                    if ok:
                        state.actions_taken.append(record)
                        verified_since_action = False
                        self._emit(
                            state,
                            Phase.RESULT,
                            str(payload.get("message", "Action applied."))
                            if isinstance(payload, dict)
                            else "Action applied.",
                            tool=name,
                            target=target or None,
                            success=True,
                        )
                    else:
                        error = (
                            payload.get("error")
                            if isinstance(payload, dict)
                            else outcome.get("error")
                        ) or "ACTION_FAILED"
                        record["error"] = error
                        state.failed_actions.append(record)
                        pending_adaptation = True
                        self._emit(
                            state,
                            Phase.FAILED,
                            str(error),
                            tool=name,
                            target=target or None,
                            success=False,
                        )
                elif kind == "verification" and ok:
                    state.latest_verification = payload
                    verified_since_action = True
                    self._emit(
                        state,
                        Phase.RESULT,
                        f"contained={payload['contained']} risk_score={payload['risk_score']} "
                        f"remaining_threats={len(payload['remaining_threats'])}",
                        tool=name,
                        success=True,
                    )
                else:
                    if ok:
                        count = len(payload) if isinstance(payload, list) else 1
                        state.observations.append(
                            {"tool": name, "target": target, "records": count, "step": state.step}
                        )
                    else:
                        pending_adaptation = True
                        self._emit(
                            state,
                            Phase.FAILED,
                            str(outcome.get("error") or "TOOL_ERROR")
                            + (f": {outcome['detail']}" if outcome.get("detail") else ""),
                            tool=name,
                            success=False,
                        )

                response_parts.append(
                    types.Part.from_function_response(name=name, response=outcome)
                )

            for call in dropped:
                response_parts.append(
                    types.Part.from_function_response(
                        name=call.name or "unknown",
                        response={
                            "success": False,
                            "error": "TOOL_CALL_LIMIT",
                            "detail": (
                                f"at most {MAX_TOOL_CALLS_PER_TURN} tool calls per turn; "
                                "this one was not run — ask again only if you still need it"
                            ),
                        },
                    )
                )

            self._advance_world(state)
            response_parts.append(
                types.Part(text=f"SIMULATION CLOCK is now {self.env.get_current_time()}.")
            )
            contents.append(types.Content(role="user", parts=response_parts))
        else:
            state.status = AgentStatus.MAX_STEPS_REACHED
            state.final_outcome = (
                f"Step ceiling of {self.max_steps} reached; handing back to a human operator."
            )
            self._emit(state, Phase.FINAL, state.final_outcome)
            return state

        verification = state.latest_verification or {}
        if self._halted():
            state.status = AgentStatus.EMERGENCY_STOPPED
        elif verification.get("contained"):
            state.status = AgentStatus.CONTAINED
        else:
            state.status = AgentStatus.NEEDS_HUMAN

        state.final_outcome = state.summary or state.status.value
        self._emit(state, Phase.COMPLETE, state.final_outcome)
        return state
