"""Execution state and structured lifecycle events for the agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Phase(str, Enum):
    OBSERVE = "OBSERVE"
    COMPLETE = "COMPLETE"
    DECIDE = "DECIDE"
    ACT = "ACT"
    EVALUATE = "EVALUATE"
    ADAPT = "ADAPT"
    RESULT = "RESULT"
    FAILED = "FAILED"
    FINAL = "FINAL"


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    INVESTIGATING = "INVESTIGATING"
    CONTAINING = "CONTAINING"
    VERIFYING = "VERIFYING"
    CONTAINED = "CONTAINED"
    NEEDS_HUMAN = "NEEDS_HUMAN"
    EMERGENCY_STOPPED = "EMERGENCY_STOPPED"
    MAX_STEPS_REACHED = "MAX_STEPS_REACHED"
    ERROR = "ERROR"


@dataclass
class AgentEvent:
    step: int
    phase: Phase
    message: str
    tool: Optional[str] = None
    target: Optional[str] = None
    success: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class AgentState:
    """In-memory record of one incident run."""

    goal: str
    step: int = 0
    phase: Phase = Phase.OBSERVE
    status: AgentStatus = AgentStatus.INVESTIGATING
    tools_called: List[str] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    failed_actions: List[Dict[str, Any]] = field(default_factory=list)
    adaptations: List[str] = field(default_factory=list)
    latest_verification: Optional[Dict[str, Any]] = None
    events: List[AgentEvent] = field(default_factory=list)
    summary: str = ""
    final_outcome: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "step": self.step,
            "phase": self.phase.value,
            "status": self.status.value,
            "tools_called": list(self.tools_called),
            "observations": list(self.observations),
            "actions_taken": list(self.actions_taken),
            "failed_actions": list(self.failed_actions),
            "adaptations": list(self.adaptations),
            "latest_verification": self.latest_verification,
            "events": [e.to_dict() for e in self.events],
            "summary": self.summary,
            "final_outcome": self.final_outcome,
        }
