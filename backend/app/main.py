"""FastAPI entrypoint for the Trinetra cyber range.

    cd backend && ./venv/bin/uvicorn app.main:app --reload

One process owns one in-memory range (environment, Red Engine, safety governor
and agent). Nothing is persisted.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router

app = FastAPI(
    title="Trinetra Cyber Range API",
    version="0.4.0",
    description=(
        "Control and observe the synthetic Nexora range: simulation clock, "
        "Operation Maya, the Blue tool allowlist and the autonomous commander."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
