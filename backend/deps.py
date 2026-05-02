"""Shared dependency types — avoids circular imports between agents and tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from backend.cost_tracker import CostTracker
from backend.sandbox import DockerSandbox

if TYPE_CHECKING:
    from backend.message_bus import FindingMessageBus
    from backend.output_types import SemgrepFinding

# Type for the triage submit callback: (verdict_dict) -> display_str
TriageSubmitFn = Callable[[dict], Coroutine[Any, Any, str]]


@dataclass
class SolverDeps:
    sandbox: DockerSandbox
    finding_id: str
    target_dir: str
    cost_tracker: CostTracker | None = None
    message_bus: FindingMessageBus | None = None
    model_spec: str = ""
    triage_fn: TriageSubmitFn | None = None
    notify_coordinator: Callable[[str], Coroutine[Any, Any, None]] | None = None


@dataclass
class CoordinatorDeps:
    cost_tracker: CostTracker
    settings: Any
    findings: list[Any] = field(default_factory=list)  # list[SemgrepFinding]
    model_specs: list[str] = field(default_factory=list)
    findings_dir: str = "findings"
    max_concurrent_findings: int = 4

    msg_port: int = 0

    # STRATEGY: per-solver step budget and total run cost ceiling
    max_solver_steps: int = 30
    budget_usd: float = 10.0

    # Runtime state
    coordinator_inbox: asyncio.Queue = field(default_factory=asyncio.Queue)
    operator_inbox: asyncio.Queue = field(default_factory=asyncio.Queue)
    swarms: dict[str, Any] = field(default_factory=dict)
    swarm_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    results: dict[str, dict] = field(default_factory=dict)
