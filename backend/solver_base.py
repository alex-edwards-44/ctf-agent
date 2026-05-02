"""Solver result type, status constants, and solver protocol — shared across all backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

# Status constants
TRIAGE_DONE = "triage_done"    # solver submitted a triage verdict
GAVE_UP = "gave_up"
CANCELLED = "cancelled"
ERROR = "error"
QUOTA_ERROR = "quota_error"
# STRATEGY: per-solver step budget — returned when solver hits --max-solver-steps
STEP_LIMIT = "step_limit"


@dataclass
class SolverResult:
    verdict: Any          # TriageVerdict | None
    status: str
    findings_summary: str
    step_count: int
    cost_usd: float
    log_path: str


class SolverProtocol(Protocol):
    """Common interface for all solver backends."""

    model_spec: str
    agent_name: str
    sandbox: object

    async def start(self) -> None: ...
    async def run_until_done_or_gave_up(self) -> SolverResult: ...
    def bump(self, insights: str) -> None: ...
    async def stop(self) -> None: ...
