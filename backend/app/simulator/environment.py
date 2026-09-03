"""The simulated cyber environment Nexora Systems runs on.

`CyberEnvironment` owns one mutable `EnvironmentState` and hands out snapshots
of it. State is rebuilt from a pure scenario builder, so `reset()` always
reproduces the exact same starting point regardless of what was mutated.

Phase 1B adds a deterministic simulation clock with an event queue, and a
`SafetyGovernor` that can pause, resume, emergency-stop and restore the range.
Time never comes from the wall clock, nothing sleeps, and nothing is random.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from app.models.environment import (
    EnvironmentState,
    ScheduledEvent,
    ScheduledEventStatus,
    Severity,
    SimulationStatus,
    TelemetryEvent,
    TelemetrySource,
)
from app.simulator.scenarios import DEFAULT_SCENARIO, SCENARIO_BUILDERS, available_scenarios


class SimulationHalted(RuntimeError):
    """Raised when a mutation is attempted while the range is emergency-stopped."""


def _parse(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def _shift(timestamp: str, seconds: int) -> str:
    return (_parse(timestamp) + timedelta(seconds=seconds)).isoformat()


class CyberEnvironment:
    """A deterministic, in-memory model of the Nexora Systems estate."""

    def __init__(
        self,
        scenario: str = DEFAULT_SCENARIO,
        faults: Optional[Dict[str, bool]] = None,
    ) -> None:
        self._scenario = self._validate(scenario)
        self._state = SCENARIO_BUILDERS[self._scenario]()
        # Deterministic fault injection for response tools; survives reset().
        self.faults: Dict[str, bool] = dict(faults or {})
        self.safety = SafetyGovernor(self)
        self._event_seq = 0
        # Called with each processed event, after its telemetry is emitted.
        # A simulation driver (e.g. the Red Engine) registers its mutations here.
        self.event_handlers: List[Callable[[ScheduledEvent], None]] = []

    def set_fault(self, name: str, enabled: bool = True) -> None:
        """Enable or disable a named, deterministic tool failure."""
        self.faults[name] = enabled

    @property
    def scenario(self) -> str:
        """Name of the scenario currently loaded."""
        return self._scenario

    @property
    def state(self) -> EnvironmentState:
        """The live, mutable state object. Mutate this to act on the estate."""
        return self._state

    def get_state(self) -> Dict[str, Any]:
        """Return a JSON-serializable observable snapshot, without hidden state."""
        return self._state.to_dict()

    def get_hidden_state(self) -> Dict[str, Any]:
        """Internal simulation truth. For the simulator and a future Red Engine only."""
        return self._state.to_dict(include_hidden=True)["hidden"]

    def load_scenario(self, scenario: str) -> EnvironmentState:
        """Replace the current state with a freshly built scenario."""
        self._scenario = self._validate(scenario)
        self._state = SCENARIO_BUILDERS[self._scenario]()
        return self._state

    def reset(self) -> EnvironmentState:
        """Rebuild the current scenario, discarding every mutation."""
        self._state = SCENARIO_BUILDERS[self._scenario]()
        self._event_seq = 0
        return self._state

    # -- simulation clock and event queue ---------------------------------

    def get_current_time(self) -> str:
        """The current simulation time as an ISO-8601 timestamp."""
        return self._state.clock.current_time

    def schedule_event(
        self,
        name: str,
        delay_seconds: int,
        category: str = "simulation",
        attack_capable: bool = False,
        payload: Optional[Dict[str, Any]] = None,
    ) -> ScheduledEvent:
        """Queue an event `delay_seconds` of simulation time from now."""
        self._require_mutable()
        clock = self._state.clock
        self._event_seq += 1
        event = ScheduledEvent(
            event_id=f"sched-{9000 + self._event_seq}",
            name=name,
            category=category,
            scheduled_at=_shift(clock.current_time, delay_seconds),
            attack_capable=attack_capable,
            payload=dict(payload or {}),
        )
        clock.scheduled_events.append(event)
        clock.scheduled_events.sort(key=lambda e: (e.scheduled_at, e.event_id))
        return event

    def advance_time(self, seconds: int) -> List[ScheduledEvent]:
        """Move simulation time forward and process everything that comes due.

        No-op while paused; refused outright once emergency-stopped.
        """
        self._require_mutable()
        if self._state.safety.simulation_status is SimulationStatus.PAUSED:
            return []
        if seconds < 0:
            raise ValueError("Simulation time only moves forward.")
        clock = self._state.clock
        clock.current_time = _shift(clock.current_time, seconds)
        clock.elapsed_seconds += seconds
        self._state.simulation_time = clock.current_time
        if self._state.safety.simulation_status is SimulationStatus.READY:
            self._state.safety.simulation_status = SimulationStatus.RUNNING
        return self.process_due_events()

    def process_due_events(self) -> List[ScheduledEvent]:
        """Fire every queued event whose time has arrived, oldest first."""
        self._require_mutable()
        clock = self._state.clock
        now = _parse(clock.current_time)
        due = [e for e in clock.scheduled_events if _parse(e.scheduled_at) <= now]
        fired: List[ScheduledEvent] = []
        for event in due:
            # A handler may emergency-stop mid-batch; the rest of the queue is
            # then left alone (the governor cancels what it needs to).
            if self._state.safety.mutations_locked or event not in clock.scheduled_events:
                break
            clock.scheduled_events.remove(event)
            event.status = ScheduledEventStatus.PROCESSED
            clock.processed_events.append(event)
            self._emit_telemetry(event)
            for handler in self.event_handlers:
                handler(event)
            fired.append(event)
        return fired

    def _emit_telemetry(self, event: ScheduledEvent) -> None:
        """Record a processed event on the unified telemetry bus."""
        payload = event.payload
        if not payload:
            return
        self._state.telemetry.append(
            TelemetryEvent(
                id=f"tel-{event.event_id}",
                timestamp=event.scheduled_at,
                source=TelemetrySource(payload.get("source", TelemetrySource.ENDPOINT.value)),
                category=payload.get("category", event.category),
                event_type=payload.get("event_type", event.name),
                severity=Severity(payload.get("severity", Severity.INFO.value)),
                message=payload.get("message", f"Scheduled event {event.name} processed."),
                related_user=payload.get("related_user"),
                related_asset=payload.get("related_asset"),
                metadata=payload.get("metadata", {}),
            )
        )

    def _require_mutable(self) -> None:
        if self._state.safety.mutations_locked:
            raise SimulationHalted(
                "Simulation is emergency-stopped; mutations are refused until "
                "restore_baseline() is called."
            )

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


class SafetyGovernor:
    """The kill switch for the range.

    Owns `simulation_status` and the resilience state. Scoring stays trivial in
    this phase: the score sits at its baseline and later phases move it.
    """

    def __init__(self, env: CyberEnvironment) -> None:
        self._env = env

    @property
    def status(self) -> SimulationStatus:
        return self._env.state.safety.simulation_status

    @property
    def resilience_score(self) -> int:
        return self._env.state.safety.resilience_score

    @property
    def critical_failure(self) -> bool:
        """True once resilience has fallen to the critical threshold."""
        safety = self._env.state.safety
        return safety.resilience_score <= safety.critical_failure_threshold

    def pause(self) -> SimulationStatus:
        """Freeze simulation time. Telemetry already recorded is kept."""
        safety = self._env.state.safety
        if safety.simulation_status is not SimulationStatus.EMERGENCY_STOPPED:
            safety.simulation_status = SimulationStatus.PAUSED
        return safety.simulation_status

    def resume(self) -> SimulationStatus:
        """Let simulation time move again after a pause."""
        safety = self._env.state.safety
        if safety.simulation_status is SimulationStatus.PAUSED:
            safety.simulation_status = SimulationStatus.RUNNING
        return safety.simulation_status

    def emergency_stop(self, reason: str) -> Dict[str, Any]:
        """Halt the range: freeze time, cancel staged attack-capable events,
        lock further mutations, and leave the forensic record untouched."""
        state = self._env.state
        safety = state.safety
        clock = state.clock
        cancelled = [e for e in clock.scheduled_events if e.attack_capable]
        for event in cancelled:
            clock.scheduled_events.remove(event)
            event.status = ScheduledEventStatus.CANCELLED
            clock.cancelled_events.append(event)
        safety.simulation_status = SimulationStatus.EMERGENCY_STOPPED
        safety.emergency_stop_reason = reason
        safety.emergency_stopped_at = clock.current_time
        safety.mutations_locked = True
        return {
            "status": safety.simulation_status.value,
            "reason": reason,
            "stopped_at": clock.current_time,
            "cancelled_events": [e.event_id for e in cancelled],
            "telemetry_preserved": len(state.telemetry),
        }

    def restore_baseline(self) -> SimulationStatus:
        """Rebuild the scenario from scratch: clock, queue and resilience reset."""
        self._env.reset()
        self._env.state.safety.simulation_status = SimulationStatus.READY
        return self._env.state.safety.simulation_status
