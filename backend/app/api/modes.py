"""Operating modes: who is allowed to act on the range.

AUTONOMOUS — the agent investigates and contains on its own.
COPILOT    — the agent investigates and proposes; a human approves each action.
TRAINING   — a human works the incident with the same Blue tools; the agent does
             not contain anything, and the run is scored at the end.

The mode changes *who* may call a state-changing tool. It never changes the
tools themselves, the range, or the safety governor, which overrides all three.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class OperationMode(str, Enum):
    AUTONOMOUS = "AUTONOMOUS"
    COPILOT = "COPILOT"
    TRAINING = "TRAINING"


class RecommendationStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


_ids = itertools.count(1)


@dataclass
class Recommendation:
    """One defensive action the agent proposed and a human has yet to rule on."""

    tool_name: str
    arguments: Dict[str, Any]
    impact: str
    reason: str
    proposed_at: str
    id: str = field(default_factory=lambda: f"rec-{next(_ids):04d}")
    status: RecommendationStatus = RecommendationStatus.PENDING
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "impact": self.impact,
            "reason": self.reason,
            "proposed_at": self.proposed_at,
            "status": self.status.value,
            "result": self.result,
        }


@dataclass
class TrainingSession:
    """A human-run exercise: where it started, what the analyst did."""

    started_at: str
    starting_risk: int
    starting_resilience: int
    actions: List[Dict[str, Any]] = field(default_factory=list)
    active: bool = True
    debrief: Optional[Dict[str, Any]] = None

    def record(self, entry: Dict[str, Any]) -> None:
        self.actions.append(entry)

    def to_dict(self, simulation_time: str) -> Dict[str, Any]:
        mutations = [a for a in self.actions if not a["read_only"]]
        return {
            "active": self.active,
            "started_at": self.started_at,
            "starting_risk": self.starting_risk,
            "starting_resilience": self.starting_resilience,
            "elapsed_simulation_time": _elapsed(self.started_at, simulation_time),
            "actions_taken": len(mutations),
            "tools_used": len(self.actions),
            "actions": self.actions,
            "debrief": self.debrief,
        }


def _elapsed(start: str, now: str) -> str:
    """HH:MM:SS of simulated time between two range timestamps."""
    from datetime import datetime

    delta = int((datetime.fromisoformat(now) - datetime.fromisoformat(start)).total_seconds())
    return f"{delta // 3600:02d}:{delta % 3600 // 60:02d}:{delta % 60:02d}"


# Deterministic scoring. No model is involved and no hidden state is read: every
# term below comes from the same verification a defender can run themselves.
GRADES = (
    (85, "ADVANCED RESPONDER"),
    (70, "COMPETENT RESPONDER"),
    (50, "DEVELOPING RESPONDER"),
    (0, "NEEDS TRAINING"),
)
EXPECTED_ACTIONS = 8


def score_training(
    session: TrainingSession, verification: Dict[str, Any], resilience: int
) -> Dict[str, Any]:
    """Grade a finished exercise from observable state alone."""
    mutations = [a for a in session.actions if not a["read_only"]]
    failed = [a for a in mutations if not a["success"]]
    high_impact = [a for a in mutations if a["impact"] == "HIGH" and a["success"]]
    contained = bool(verification["contained"])
    risk = int(verification["risk_score"])
    feedback: List[str] = []

    score = 100
    if not contained:
        score -= 40
        feedback.append("The incident was not contained: active threats remain.")
    else:
        feedback.append("Incident contained — verification reports no active threats.")

    score -= risk // 2
    if risk:
        feedback.append(f"Residual risk of {risk} still scores against the run.")

    lost = max(0, session.starting_resilience - resilience)
    score -= lost // 5
    if lost:
        feedback.append(f"Resilience fell {lost} points while you worked; act sooner.")

    # High-impact containment is only justified when the estate is still exposed.
    unnecessary_high = 0 if not contained else max(0, len(high_impact) - 1)
    score -= 10 * unnecessary_high
    if unnecessary_high:
        feedback.append(
            f"{unnecessary_high} high-impact action(s) beyond what containment needed."
        )

    score -= 5 * len(failed)
    if failed:
        feedback.append(f"{len(failed)} action(s) failed — check targets before acting.")

    excess = max(0, len(mutations) - EXPECTED_ACTIONS)
    score -= 3 * excess
    if excess:
        feedback.append(f"{excess} action(s) more than a tight response needs.")

    protected = [a for a in mutations if a["tool"] in ("protect_data_asset", "restrict_asset")]
    if protected and not verification["active_data_risk"]:
        score += 5
        feedback.append("Critical data assets were protected.")

    score = max(0, min(100, score))
    grade = next(name for threshold, name in GRADES if score >= threshold)
    return {
        "score": score,
        "grade": grade,
        "contained": contained,
        "final_risk": risk,
        "final_resilience": resilience,
        "actions_taken": len(mutations),
        "high_impact_actions": len(high_impact),
        "failed_actions": len(failed),
        "tools_used": len(session.actions),
        "feedback": feedback,
    }
