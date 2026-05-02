"""Triage coordinator event loop — manages the queue of Semgrep findings."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from backend.config import Settings
from backend.cost_tracker import CostTracker
from backend.deps import CoordinatorDeps
from backend.models import DEFAULT_MODELS
from backend.output_types import SemgrepFinding
from backend.scanner import SEVERITY_ORDER

logger = logging.getLogger(__name__)

# Callable type for a coordinator turn: (message) -> None
TurnFn = Callable[[str], Coroutine[Any, Any, None]]


def build_deps(
    settings: Settings,
    findings: list[SemgrepFinding],
    target_dir: str,
    model_specs: list[str] | None = None,
) -> tuple[CostTracker, CoordinatorDeps]:
    """Create cost tracker and coordinator deps for a triage run."""
    cost_tracker = CostTracker()
    specs = model_specs or list(DEFAULT_MODELS)

    deps = CoordinatorDeps(
        cost_tracker=cost_tracker,
        settings=settings,
        findings=findings,
        model_specs=specs,
        max_concurrent_findings=getattr(settings, "max_concurrent_findings", 4),
        max_solver_steps=getattr(settings, "max_solver_steps", 30),
        budget_usd=getattr(settings, "budget_usd", 10.0),
    )
    # Stash target_dir in deps for use by coordinator_core
    deps.target_dir = target_dir  # type: ignore[attr-defined]

    return cost_tracker, deps


def _sort_findings(findings: list[SemgrepFinding]) -> list[SemgrepFinding]:
    """Sort by severity descending (ERROR first), then CWE presence, then path."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            0 if f.cwe else 1,
            f.path,
            f.line,
        ),
    )


async def run_triage_loop(
    deps: CoordinatorDeps,
    cost_tracker: CostTracker,
    turn_fn: TurnFn,
    status_interval: int = 30,
) -> dict[str, Any]:
    """Drive the triage queue from start to finish.

    Auto-spawns swarms for findings in priority order, up to max_concurrent.
    Exits when all findings are triaged (or budget is hit).
    """
    sorted_findings = _sort_findings(deps.findings)
    n = len(sorted_findings)

    # Start operator message server
    msg_server = await _start_msg_server(deps.operator_inbox, deps.msg_port)

    logger.info(
        "Triage loop starting: %d finding(s), %d model(s), budget=$%.2f",
        n, len(deps.model_specs), deps.budget_usd,
    )

    summary = "\n".join(
        f"  [{i+1}] {f.severity} {f.rule_id} @ {f.path}:{f.line} (id={f.finding_id})"
        for i, f in enumerate(sorted_findings)
    )
    initial_msg = (
        f"You have {n} finding(s) to triage from Semgrep, listed in priority order "
        f"(severity descending):\n{summary}\n\n"
        f"Spawn swarms in this order up to the concurrency limit ({deps.max_concurrent_findings}). "
        f"Stop when all findings are triaged or the budget is hit."
    )

    try:
        await turn_fn(initial_msg)

        # Auto-spawn up to capacity
        for finding in sorted_findings:
            await _auto_spawn_one(deps, finding.finding_id)

        last_status = asyncio.get_event_loop().time()

        while True:
            # Check completion
            all_done = all(f.finding_id in deps.results for f in sorted_findings)
            if all_done:
                logger.info("All findings triaged — triage loop complete")
                break

            # Check budget
            if deps.budget_usd > 0 and cost_tracker.total_cost_usd >= deps.budget_usd:
                logger.warning(
                    "Budget $%.2f hit (spent $%.2f) — stopping triage loop",
                    deps.budget_usd, cost_tracker.total_cost_usd,
                )
                break

            await asyncio.sleep(2.0)

            parts: list[str] = []

            # Detect finished swarms, spawn next queued finding
            for fid, task in list(deps.swarm_tasks.items()):
                if task.done():
                    result_info = deps.results.get(fid, {})
                    verdict = result_info.get("verdict", "no verdict")
                    parts.append(f"TRIAGE DONE: '{fid}' — verdict: {verdict}")
                    deps.swarm_tasks.pop(fid, None)
                    # Spawn next queued finding if any
                    for finding in sorted_findings:
                        if finding.finding_id not in deps.results and finding.finding_id not in deps.swarms:
                            await _auto_spawn_one(deps, finding.finding_id)
                            break

            # Drain solver messages
            while True:
                try:
                    solver_msg = deps.coordinator_inbox.get_nowait()
                    parts.append(f"SOLVER MESSAGE: {solver_msg}")
                except asyncio.QueueEmpty:
                    break

            # Drain operator messages
            while True:
                try:
                    op_msg = deps.operator_inbox.get_nowait()
                    parts.append(f"OPERATOR MESSAGE: {op_msg}")
                    logger.info("Operator message: %s", op_msg[:200])
                except asyncio.QueueEmpty:
                    break

            # Periodic status
            now = asyncio.get_event_loop().time()
            if now - last_status >= status_interval:
                last_status = now
                active = [fid for fid, t in deps.swarm_tasks.items() if not t.done()]
                done_count = len(deps.results)
                status_line = (
                    f"STATUS: {done_count}/{n} triaged, "
                    f"{len(active)} active swarms. "
                    f"Cost: ${cost_tracker.total_cost_usd:.2f}"
                )
                if active or parts:
                    parts.append(status_line)
                else:
                    logger.info(status_line)

            if parts:
                msg = "\n\n".join(parts)
                logger.debug("Event → coordinator: %s", msg[:200])
                await turn_fn(msg)

    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Triage loop interrupted")
    except Exception as e:
        logger.error("Triage loop fatal: %s", e, exc_info=True)
    finally:
        if msg_server:
            msg_server.close()
            await msg_server.wait_closed()
        for swarm in deps.swarms.values():
            swarm.kill()
        for task in deps.swarm_tasks.values():
            task.cancel()
        if deps.swarm_tasks:
            await asyncio.gather(*deps.swarm_tasks.values(), return_exceptions=True)
        cost_tracker.log_summary()

    return {
        "results": deps.results,
        "total_cost_usd": cost_tracker.total_cost_usd,
        "total_tokens": cost_tracker.total_tokens,
    }


async def _auto_spawn_one(deps: CoordinatorDeps, finding_id: str) -> None:
    """Spawn a swarm for finding_id if not already running and under capacity."""
    if finding_id in deps.results:
        return
    if finding_id in deps.swarms:
        return

    # STRATEGY: cost-aware early stopping
    budget = deps.budget_usd
    if budget > 0 and deps.cost_tracker.total_cost_usd >= budget:
        logger.warning(
            "STRATEGY: budget $%.2f reached — skipping swarm for '%s'",
            budget, finding_id,
        )
        return

    active = sum(1 for t in deps.swarm_tasks.values() if not t.done())
    if active >= deps.max_concurrent_findings:
        return

    try:
        from backend.agents.coordinator_core import do_spawn_swarm
        result = await do_spawn_swarm(deps, finding_id)
        logger.info("Auto-spawn %s: %s", finding_id, result[:100])
    except Exception as e:
        logger.warning("Auto-spawn failed for %s: %s", finding_id, e)


async def _start_msg_server(inbox: asyncio.Queue, port: int = 0) -> asyncio.Server | None:
    """Start a tiny HTTP server for operator messages via POST."""

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    k, v = line.decode().split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            method = request_line.decode().split()[0] if request_line else ""
            content_length = int(headers.get("content-length", 0))

            if method == "POST" and content_length > 0:
                body = await asyncio.wait_for(reader.read(content_length), timeout=5)
                try:
                    data = json.loads(body)
                    message = data.get("message", body.decode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    message = body.decode("utf-8", errors="replace")

                inbox.put_nowait(message)
                resp = json.dumps({"ok": True, "queued": message[:200]})
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(resp)}\r\n\r\n{resp}".encode()
                )
            else:
                resp = json.dumps({"error": "POST with JSON body required"})
                writer.write(
                    f"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {len(resp)}\r\n\r\n{resp}".encode()
                )
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    try:
        server = await asyncio.start_server(_handle, "127.0.0.1", port)
        actual_port = server.sockets[0].getsockname()[1]
        logger.info("Operator message endpoint: http://127.0.0.1:%d", actual_port)
        return server
    except OSError as e:
        logger.warning("Could not start operator message endpoint: %s", e)
        return None
