"""TrinetraAgent — the autonomous loop around the Phase 2 tools.

The controller owns safety and bookkeeping only: allowlisting, argument
validation, the step ceiling and the rule that containment cannot be declared
without a fresh verification. Which tools to call, in what order, and what to do
about a failure are decided entirely by the model.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from app.agent.models import AgentEvent, AgentState, AgentStatus, Phase
from app.agent.prompts import SYSTEM_INSTRUCTION
from app.agent.tool_registry import REGISTRY, call_tool, function_declarations, target_of
from app.simulator.environment import CyberEnvironment

MAX_STEPS = 12
MAX_NUDGES = 2
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

EventSink = Callable[[AgentEvent], None]


class AgentConfigurationError(RuntimeError):
    """Raised when the agent cannot be constructed (missing key, missing SDK)."""


def _load_api_key(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    try:  # optional convenience only
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
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
        model: str = DEFAULT_MODEL,
        max_steps: int = MAX_STEPS,
        client: Any = None,
        on_event: Optional[EventSink] = None,
    ) -> None:
        self.env = env
        self.model = model
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

    # ── model call ───────────────────────────────────────────────
    def _config(self) -> Any:
        from google.genai import types

        return types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=[types.Tool(function_declarations=function_declarations())],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            temperature=0.2,
        )

    def run(self, goal: str) -> AgentState:
        from google.genai import types

        state = AgentState(goal=goal)
        contents: List[Any] = [
            types.Content(role="user", parts=[types.Part(text=f"OPERATOR GOAL: {goal}")])
        ]
        nudges = 0
        pending_adaptation = False
        verified_since_action = True

        while state.step < self.max_steps:
            state.step += 1

            try:
                response = self.client.models.generate_content(
                    model=self.model, contents=contents, config=self._config()
                )
            except Exception as exc:
                self._emit(state, Phase.FAILED, f"Gemini API error: {_shorten(str(exc), 180)}")
                state.status = AgentStatus.NEEDS_HUMAN
                return state

            candidate = (response.candidates or [None])[0]
            parts = list(getattr(getattr(candidate, "content", None), "parts", None) or [])
            contents.append(
                candidate.content
                if candidate is not None and candidate.content is not None
                else types.Content(role="model", parts=[])
            )

            rationale = " ".join(p.text.strip() for p in parts if getattr(p, "text", None))
            calls = [p.function_call for p in parts if getattr(p, "function_call", None)]

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

            contents.append(types.Content(role="user", parts=response_parts))
        else:
            state.status = AgentStatus.MAX_STEPS_REACHED
            self._emit(
                state,
                Phase.FINAL,
                f"Step ceiling of {self.max_steps} reached; handing back to a human operator.",
            )
            return state

        verification = state.latest_verification or {}
        if verification.get("contained"):
            state.status = AgentStatus.CONTAINED
        elif state.status is not AgentStatus.MAX_STEPS_REACHED:
            state.status = AgentStatus.NEEDS_HUMAN

        self._emit(state, Phase.FINAL, state.summary or state.status.value)
        return state
