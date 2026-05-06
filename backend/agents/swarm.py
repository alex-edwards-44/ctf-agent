"""FindingSwarm — parallel solvers racing to triage one Semgrep finding."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from backend.agents.claude_solver import ClaudeSolver
from backend.agents.gemini_solver import GeminiSolver
from backend.agents.openai_solver import OpenAISolver
from backend.cost_tracker import CostTracker
from backend.message_bus import FindingMessageBus
from backend.models import DEFAULT_MODELS, provider_from_spec
from backend.output_types import SemgrepFinding, TriageVerdict
from backend.solver_base import (
    CANCELLED,
    ERROR,
    GAVE_UP,
    QUOTA_ERROR,
    STEP_LIMIT,
    TRIAGE_DONE,
    SolverProtocol,
    SolverResult,
)

if TYPE_CHECKING:
    from backend.config import Settings

logger = logging.getLogger(__name__)


@dataclass
class FindingSwarm:
    """Parallel solvers racing to triage one Semgrep finding."""

    finding: SemgrepFinding
    target_dir: str
    cost_tracker: CostTracker
    settings: Settings
    model_specs: list[str] = field(default_factory=lambda: list(DEFAULT_MODELS))
    coordinator_inbox: asyncio.Queue | None = None

    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    solvers: dict[str, SolverProtocol] = field(default_factory=dict)
    solver_insights: dict[str, str] = field(default_factory=dict)
    winner: SolverResult | None = None
    verdict: TriageVerdict | None = None
    message_bus: FindingMessageBus = field(default_factory=FindingMessageBus)

    # Temporary JSON file written for this finding (cleaned up on stop)
    _finding_json_path: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        # Write the finding JSON to a temp file so the sandbox can mount it
        import tempfile
        fj = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix=f"finding-{self.finding.finding_id}-",
            delete=False,
        )
        json.dump(
            {
                "finding_id": self.finding.finding_id,
                "path": self.finding.path,
                "line": self.finding.line,
                "rule_id": self.finding.rule_id,
                "severity": self.finding.severity,
                "message": self.finding.message,
                "code_snippet": self.finding.code_snippet,
                "cwe": self.finding.cwe,
            },
            fj,
            indent=2,
        )
        fj.close()
        self._finding_json_path = fj.name

    def _create_solver(self, model_spec: str) -> ClaudeSolver | GeminiSolver | OpenAISolver:
        provider = provider_from_spec(model_spec)
        notify = self._make_notify_fn(model_spec)
        common = dict(
            model_spec=model_spec,
            finding=self.finding,
            target_dir=self.target_dir,
            finding_json_path=self._finding_json_path,
            cost_tracker=self.cost_tracker,
            settings=self.settings,
            cancel_event=self.cancel_event,
            message_bus=self.message_bus,
            notify_coordinator=notify,
        )

        if provider == "claude-sdk":
            return ClaudeSolver(**common)
        if provider == "google":
            return GeminiSolver(**common)
        if provider == "openai":
            return OpenAISolver(**common)

        raise ValueError(
            f"Unsupported provider '{provider}' in spec '{model_spec}'. "
            "Supported providers: claude-sdk, google, openai."
        )

    def _make_notify_fn(self, model_spec: str):
        async def _notify(message: str) -> None:
            if self.coordinator_inbox:
                self.coordinator_inbox.put_nowait(
                    f"[{self.finding.finding_id}/{model_spec}] {message}"
                )
        return _notify

    def _gather_sibling_insights(self, exclude_model: str) -> str:
        parts = [
            f"[{m}]: {insight}"
            for m, insight in self.solver_insights.items()
            if m != exclude_model and insight
        ]
        return "\n\n".join(parts) if parts else "No sibling insights available yet."

    async def _run_solver(self, model_spec: str) -> SolverResult | None:
        try:
            solver = self._create_solver(model_spec)
        except ValueError as e:
            logger.warning(
                "[%s] Solver spawn failed for %s (provider=%s): %s",
                self.finding.finding_id,
                model_spec,
                provider_from_spec(model_spec),
                e,
            )
            return None

        self.solvers[model_spec] = solver
        try:
            result, final_solver = await self._run_solver_loop(solver, model_spec)
            solver = final_solver
            return result
        except Exception as e:
            logger.error(
                "[%s/%s] Fatal solver error: %s",
                self.finding.finding_id, model_spec, e, exc_info=True,
            )
            return None
        finally:
            await solver.stop()

    async def _run_solver_loop(
        self, solver: ClaudeSolver, model_spec: str
    ) -> tuple[SolverResult, ClaudeSolver]:
        bump_count = 0
        consecutive_errors = 0
        result = SolverResult(
            verdict=None, status=CANCELLED, findings_summary="",
            step_count=0, cost_usd=0.0, log_path="",
        )
        await solver.start()

        while not self.cancel_event.is_set():
            result = await solver.run_until_done_or_gave_up()

            # Broadcast useful insights to siblings
            if (result.status not in (ERROR, QUOTA_ERROR)
                    and not (result.step_count == 0 and result.cost_usd == 0)
                    and result.findings_summary
                    and not result.findings_summary.startswith(("Error:", "Turn failed:"))):
                self.solver_insights[model_spec] = result.findings_summary
                await self.message_bus.post(model_spec, result.findings_summary[:500])

            if result.status == TRIAGE_DONE:
                self.cancel_event.set()
                self.winner = result
                self.verdict = result.verdict
                logger.info(
                    "[%s] Verdict from %s: %s",
                    self.finding.finding_id, model_spec,
                    result.verdict.verdict if result.verdict else "?",
                )
                return result, solver

            if result.status == CANCELLED:
                break

            # STRATEGY: step budget exhausted — stop cleanly without bumping
            if result.status == STEP_LIMIT:
                logger.info(
                    "[%s/%s] Step budget exhausted after %d steps — not bumping",
                    self.finding.finding_id, model_spec, result.step_count,
                )
                break

            if result.status == QUOTA_ERROR:
                logger.warning("[%s/%s] Quota error — stopping", self.finding.finding_id, model_spec)
                break

            if result.status in (GAVE_UP, ERROR):
                if result.step_count == 0 and result.cost_usd == 0:
                    logger.warning("[%s/%s] Broken (0 steps, $0) — not bumping", self.finding.finding_id, model_spec)
                    break

                if result.status == ERROR:
                    consecutive_errors += 1
                    if consecutive_errors >= 3:
                        logger.warning("[%s/%s] %d consecutive errors — giving up", self.finding.finding_id, model_spec, consecutive_errors)
                        break
                else:
                    consecutive_errors = 0

                bump_count += 1
                try:
                    await asyncio.wait_for(
                        self.cancel_event.wait(),
                        timeout=min(bump_count * 30, 300),
                    )
                    break
                except TimeoutError:
                    pass
                insights = self._gather_sibling_insights(model_spec)
                solver.bump(insights)
                logger.info("[%s/%s] Bumped (%d)", self.finding.finding_id, model_spec, bump_count)
                continue

        return result, solver

    async def run(self) -> SolverResult | None:
        """Run all solvers in parallel. Returns winner's result or None."""
        # Pre-validate: fail loudly if no supported provider can be created
        valid_specs: list[str] = []
        for spec in self.model_specs:
            provider = provider_from_spec(spec)
            if provider not in ("claude-sdk", "google", "openai"):
                logger.warning(
                    "[%s] Skipping unknown provider '%s' in spec '%s'",
                    self.finding.finding_id, provider, spec,
                )
            else:
                valid_specs.append(spec)

        if not valid_specs:
            raise RuntimeError(
                f"[{self.finding.finding_id}] No supported providers — "
                f"all specs failed validation: {self.model_specs}"
            )

        tasks = [
            asyncio.create_task(self._run_solver(spec), name=f"solver-{spec}")
            for spec in valid_specs
        ]

        result: SolverResult | None = None
        try:
            while tasks:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    try:
                        r = task.result()
                    except Exception:
                        continue
                    if r and r.status == TRIAGE_DONE:
                        result = r
                        return result

                tasks = list(pending)

            return self.winner
        except Exception as e:
            logger.error("[%s] Swarm error: %s", self.finding.finding_id, e, exc_info=True)
            return None
        finally:
            # Always cancel any still-running solver tasks and wait for their
            # stop() calls to complete — this closes Docker clients and prevents
            # unclosed aiohttp session warnings.  Runs on normal return, on
            # exception, AND on CancelledError (which except Exception misses).
            self.cancel_event.set()
            for t in tasks:
                if not t.done():
                    t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Clean up the temporary finding JSON
            if self._finding_json_path:
                try:
                    Path(self._finding_json_path).unlink(missing_ok=True)
                except Exception:
                    pass

    def kill(self) -> None:
        self.cancel_event.set()

    def get_status(self) -> dict:
        return {
            "finding_id": self.finding.finding_id,
            "rule_id": self.finding.rule_id,
            "severity": self.finding.severity,
            "cancelled": self.cancel_event.is_set(),
            "verdict": self.verdict.verdict if self.verdict else None,
            "agents": {
                spec: {
                    "insights": self.solver_insights.get(spec, ""),
                    "status": "running" if spec in self.solvers and not self.cancel_event.is_set()
                             else ("won" if self.winner else "finished"),
                }
                for spec in self.model_specs
            },
        }
