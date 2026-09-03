"""TrinetraAgent — the autonomous loop around the Phase 2 tools.

The controller owns safety and bookkeeping only: allowlisting, argument
validation, the step ceiling and the rule that containment cannot be declared
without a fresh verification. Which tools to call, in what order, and what to do
about a failure are decided entirely by the model.
"""

from __future__ import annotations

import os
import time
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
DEFAULT_MODEL = "gemini-3.5-flash"
DEFAULT_FALLBACK_MODEL = "gemini-3.1-flash-lite"
RETRY_DELAY_SECONDS = 2.0
# Transient conditions worth another attempt; anything else (bad key, bad
# request, permission, schema) is a real error and must surface immediately.
RETRYABLE_MARKERS = (
    "429", "500", "502", "503", "504", "timeout", "timed out", "deadline",
    "unavailable", "resource_exhausted", "internal error", "overloaded",
)
FATAL_MARKERS = (
    "400", "401", "403", "404", "unauthenticated", "permission", "invalid api key",
    "api key not valid", "invalid_argument", "not found",
)

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
        self.fallback_model = (
            os.environ.get("GEMINI_FALLBACK_MODEL", "").strip() or DEFAULT_FALLBACK_MODEL
        )
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

    # ── verification bookkeeping ─────────────────────────────────
    def _record_verification(
        self, state: AgentState, payload: Dict[str, Any], tool: str, adapted_after: int
    ) -> Any:
        """Log a verification result and, if containment fell short, mark an ADAPT.

        The adaptation is recognised from observable verification output only.
        What to do next is left entirely to the model.
        """
        state.latest_verification = payload
        self._emit(
            state,
            Phase.RESULT,
            f"contained={payload['contained']} risk_score={payload['risk_score']} "
            f"remaining_threats={len(payload['remaining_threats'])}",
            tool=tool,
            success=True,
        )
        if payload["contained"] or len(state.actions_taken) <= adapted_after:
            return adapted_after, ""
        remaining = ", ".join(
            f"{t['type']}:{t['target']}" for t in payload["remaining_threats"][:3]
        ) or "no single target isolated"
        summary = (
            "The previous containment action was insufficient: verification reports "
            f"{len(payload['remaining_threats'])} remaining active threat(s) at risk "
            f"{payload['risk_score']} ({remaining})."
        )
        state.adaptations.append(summary)
        self._emit(state, Phase.ADAPT, summary + " Reassessing strategy.", tool=tool)
        return len(state.actions_taken), (
            "The previous containment action was insufficient. Verification shows "
            "remaining active threats. Reassess using current observable evidence "
            "and choose your next step."
        )

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

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        text = str(exc).lower()
        if any(marker in text for marker in FATAL_MARKERS):
            return False
        return any(marker in text for marker in RETRYABLE_MARKERS)

    def _generate(self, contents: List[Any]) -> Any:
        """One model request: primary, one retry, then one fallback attempt.

        The same `contents` are reused throughout, so a model switch keeps the
        whole investigation — no turn is replayed and nothing restarts.
        """
        last: Exception = RuntimeError("no model attempt was made")
        candidates = [(self.model, MODEL_RETRIES)]
        if self.fallback_model and self.fallback_model != self.model:
            candidates.append((self.fallback_model, 0))
        for index, (model, retries) in enumerate(candidates):
            if index:
                print(f"Switching to fallback model: {model}", flush=True)
            for attempt in range(retries + 1):
                print("Waiting for Gemini decision...", flush=True)
                try:
                    response = self.client.models.generate_content(
                        model=model, contents=contents, config=self._config()
                    )
                    self.model = model  # stay on whichever model answered
                    return response
                except Exception as exc:
                    last = exc
                    if not self._is_retryable(exc):
                        raise
                    if attempt < retries:
                        print("Primary model unavailable — retrying...", flush=True)
                        time.sleep(RETRY_DELAY_SECONDS)
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
        adapted_after_actions = 0

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
            adapt_note = ""
            acted_this_cycle = False
            world_advanced = False
            for call in calls:
                name = call.name or ""
                args: Dict[str, Any] = dict(call.args or {})
                spec = REGISTRY.get(name)
                kind = spec.kind if spec else "unknown"
                target = target_of(name, args)

                if kind == "defensive" and acted_this_cycle:
                    # One state-changing action per decision cycle: the model sees
                    # what the first one did before choosing another.
                    response_parts.append(
                        types.Part.from_function_response(
                            name=name,
                            response={
                                "success": False,
                                "error": "ONE_ACTION_PER_CYCLE",
                                "detail": (
                                    "a defensive action was already applied this turn and "
                                    "verified; review the verification, then act again if "
                                    "the evidence still supports it"
                                ),
                            },
                        )
                    )
                    continue

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
                        # Let the world move, then verify straight away so the next
                        # decision is made against the estate as it now stands.
                        acted_this_cycle = True
                        self._advance_world(state)
                        world_advanced = True
                        state.status = AgentStatus.VERIFYING
                        self._emit(
                            state,
                            Phase.EVALUATE,
                            "Verifying the effect of that action.",
                            tool="verify_environment",
                        )
                        check = call_tool(self.env, "verify_environment", {})
                        state.tools_called.append("verify_environment")
                        if check.get("success"):
                            verified_since_action = True
                            adapted_after_actions, note = self._record_verification(
                                state, check["result"], "verify_environment", adapted_after_actions
                            )
                            adapt_note = note or adapt_note
                        response_parts.append(
                            types.Part.from_function_response(
                                name=name, response=outcome
                            )
                        )
                        response_parts.append(
                            types.Part.from_function_response(
                                name="verify_environment", response=check
                            )
                        )
                        continue
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
                    verified_since_action = True
                    adapted_after_actions, note = self._record_verification(
                        state, payload, name, adapted_after_actions
                    )
                    adapt_note = note or adapt_note
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

            if not world_advanced:
                self._advance_world(state)
            if adapt_note:
                response_parts.append(types.Part(text=adapt_note))
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
