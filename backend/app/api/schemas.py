"""Request bodies for the API. Responses stay plain dictionaries built from the
existing engine payloads, so the API adds no second source of truth."""

from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, Field


class AdvanceRequest(BaseModel):
    seconds: int = Field(default=30, ge=1, le=3600)


class LaunchRequest(BaseModel):
    scenario: str = "operation_maya"


class EmergencyStopRequest(BaseModel):
    reason: str = Field(default="Manual operator emergency stop", min_length=1, max_length=200)


class AgentRunRequest(BaseModel):
    goal: str = Field(min_length=8, max_length=1000)


class ToolCallRequest(BaseModel):
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ModeRequest(BaseModel):
    mode: str


class CopilotRunRequest(BaseModel):
    goal: str = Field(
        default="Investigate and recommend the safest next containment action.",
        min_length=8,
        max_length=1000,
    )
