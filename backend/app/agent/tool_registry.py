"""The tool surface exposed to the model.

Every entry is derived from `BLUE_TOOL_REGISTRY` — the Phase 2B allowlist — so
the agent can reach exactly the Blue tools and nothing else. Signatures are read
from the functions themselves, which keeps the declarations honest: an argument
the tool does not accept cannot be declared, and one it requires cannot be
omitted.

The Red Engine, its hidden state and the simulator's own controls are not
importable from here on purpose.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Tuple

from app.simulator.environment import CyberEnvironment
from app.tools import BLUE_TOOL_REGISTRY

Kind = str  # "investigation" | "defensive" | "verification"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: Kind
    description: str
    fn: Callable[..., Any]
    params: Dict[str, str]  # arg name -> "string" | "integer"
    required: Tuple[str, ...] = ()
    impact: str = "NONE"


def _kind(name: str, read_only: bool) -> Kind:
    if name == "verify_environment":
        return "verification"
    return "investigation" if read_only else "defensive"


def _signature(fn: Callable[..., Any]) -> Tuple[Dict[str, str], Tuple[str, ...]]:
    """Read declared arguments straight off the tool, skipping `env`."""
    params: Dict[str, str] = {}
    required: List[str] = []
    for index, (arg, param) in enumerate(inspect.signature(fn).parameters.items()):
        if index == 0:  # the environment is supplied by the controller
            continue
        annotation = str(param.annotation)
        params[arg] = "integer" if "int" in annotation and "str" not in annotation else "string"
        if param.default is inspect.Parameter.empty:
            required.append(arg)
    return params, tuple(required)


def _build_registry() -> Dict[str, ToolSpec]:
    specs: Dict[str, ToolSpec] = {}
    for name, entry in BLUE_TOOL_REGISTRY.items():
        params, required = _signature(entry["fn"])
        impact = entry["impact"]
        description = entry["description"]
        if "since" in params:
            description = (
                f"{description} `since` is a simulation-clock time on the current "
                "simulated day, as HH:MM:SS taken from the range clock — never a "
                "real-world or invented date. Omit it for everything so far."
            )
        if not entry["read_only"]:
            description = f"{description} Disruption impact: {impact}."
        specs[name] = ToolSpec(
            name=name,
            kind=_kind(name, entry["read_only"]),
            description=description,
            fn=entry["fn"],
            params=params,
            required=required,
            impact=impact,
        )
    return specs


REGISTRY: Dict[str, ToolSpec] = _build_registry()


def function_declarations() -> List[Any]:
    """Gemini FunctionDeclaration objects for every allowlisted tool."""
    from google.genai import types

    declarations = []
    for spec in REGISTRY.values():
        schema: Dict[str, Any] = {"type": "OBJECT", "properties": {}}
        for arg, arg_type in spec.params.items():
            schema["properties"][arg] = {"type": arg_type.upper()}
        if spec.required:
            schema["required"] = list(spec.required)
        declarations.append(
            types.FunctionDeclaration(
                name=spec.name,
                description=spec.description,
                parameters=schema if spec.params else None,
            )
        )
    return declarations


def _validate_since(env: CyberEnvironment, value: Any) -> str:
    """Keep `since` on the simulation clock. Returns an error detail, or ""."""
    clock = env.state.clock
    day, offset = clock.current_time[:10], clock.current_time[19:]
    text = str(value).strip()
    stamp = f"{day}T{text}{offset}" if len(text) == 8 and text.count(":") == 2 else text
    window = f"between {clock.start_time[11:19]} and {clock.current_time[11:19]} on {day}"
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return f"since must be a simulation time as HH:MM:SS, {window}; got {text!r}"
    if not (
        datetime.fromisoformat(clock.start_time)
        <= moment
        <= datetime.fromisoformat(clock.current_time)
    ):
        return f"since is outside the simulated range; use a time {window}, or omit it"
    return ""


def call_tool(env: CyberEnvironment, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate then execute an allowlisted tool. Never raises."""
    spec = REGISTRY.get(name)
    if spec is None:
        return {"success": False, "error": "UNKNOWN_TOOL", "detail": f"{name} is not available"}

    args = dict(args or {})
    unexpected = [a for a in args if a not in spec.params]
    if unexpected:
        return {
            "success": False,
            "error": "INVALID_ARGUMENTS",
            "detail": f"unexpected argument(s): {', '.join(sorted(unexpected))}",
        }
    missing = [a for a in spec.required if args.get(a) in (None, "")]
    if missing:
        return {
            "success": False,
            "error": "INVALID_ARGUMENTS",
            "detail": f"missing required argument(s): {', '.join(missing)}",
        }

    if args.get("since") not in (None, ""):
        detail = _validate_since(env, args["since"])
        if detail:
            return {"success": False, "error": "INVALID_SIMULATION_TIME", "detail": detail}

    clean: Dict[str, Any] = {}
    for arg, value in args.items():
        if value is None:
            continue
        if spec.params[arg] == "integer":
            try:
                clean[arg] = int(value)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "error": "INVALID_ARGUMENTS",
                    "detail": f"{arg} must be an integer",
                }
        else:
            if not isinstance(value, (str, int, float)):
                return {
                    "success": False,
                    "error": "INVALID_ARGUMENTS",
                    "detail": f"{arg} must be a string",
                }
            clean[arg] = str(value)

    try:
        return {"success": True, "result": spec.fn(env, **clean)}
    except Exception as exc:  # tool bugs must not kill the run
        return {"success": False, "error": "TOOL_EXECUTION_ERROR", "detail": str(exc)}


def target_of(name: str, args: Dict[str, Any]) -> str:
    """Best-effort single-value target for event display."""
    spec = REGISTRY.get(name)
    if not spec or not args:
        return ""
    for arg in (spec.required or tuple(spec.params)):
        value = args.get(arg)
        if value:
            return str(value)
    return ""
