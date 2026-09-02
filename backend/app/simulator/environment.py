"""The simulated cyber environment Nexora Systems runs on.

`CyberEnvironment` owns one mutable `EnvironmentState` and hands out snapshots
of it. State is rebuilt from a pure scenario builder, so `reset()` always
reproduces the exact same starting point regardless of what was mutated.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.environment import EnvironmentState
from app.simulator.scenarios import DEFAULT_SCENARIO, SCENARIO_BUILDERS, available_scenarios


class CyberEnvironment:
    """A deterministic, in-memory model of the Nexora Systems estate."""

    def __init__(self, scenario: str = DEFAULT_SCENARIO) -> None:
        self._scenario = self._validate(scenario)
        self._state = SCENARIO_BUILDERS[self._scenario]()

    @property
    def scenario(self) -> str:
        """Name of the scenario currently loaded."""
        return self._scenario

    @property
    def state(self) -> EnvironmentState:
        """The live, mutable state object. Mutate this to act on the estate."""
        return self._state

    def get_state(self) -> Dict[str, Any]:
        """Return a JSON-serializable snapshot; mutating it cannot affect the estate."""
        return self._state.to_dict()

    def load_scenario(self, scenario: str) -> EnvironmentState:
        """Replace the current state with a freshly built scenario."""
        self._scenario = self._validate(scenario)
        self._state = SCENARIO_BUILDERS[self._scenario]()
        return self._state

    def reset(self) -> EnvironmentState:
        """Rebuild the current scenario, discarding every mutation."""
        self._state = SCENARIO_BUILDERS[self._scenario]()
        return self._state

    @staticmethod
    def available_scenarios() -> List[str]:
        """Scenario names this environment can load."""
        return available_scenarios()

    @staticmethod
    def _validate(scenario: str) -> str:
        if scenario not in SCENARIO_BUILDERS:
            raise ValueError(
                f"Unknown scenario {scenario!r}. Available: {', '.join(available_scenarios())}"
            )
        return scenario

    def __repr__(self) -> str:
        return (
            f"CyberEnvironment(scenario={self._scenario!r}, "
            f"status={self._state.incident_status.status.value!r}, "
            f"alerts={len(self._state.security_alerts)})"
        )
