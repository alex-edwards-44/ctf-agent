"""Shared coordinator tool logic — called by the Claude SDK coordinator."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.deps import CoordinatorDeps
from backend.solver_base import TRIAGE_DONE

logger = logging.getLogger(__name__)


async def do_get_triage_status(deps: CoordinatorDeps) -> str:
    """List all findings with their current triage status."""
    rows = []
    for finding in deps.findings:
        fid = finding.finding_id
        result = deps.results.get(fid)
        swarm = deps.swarms.get(fid)
        active = fid in deps.swarm_tasks and not deps.swarm_tasks[fid].done()
        if result:
            verdict = result.get("verdict", "?")
            status = f"done:{verdict}"
        elif active:
            status = "running"
        else:
            status = "queued"
        rows.append({
            "finding_id": fid,
            "path": f"{finding.path}:{finding.line}",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "status": status,
        })
    return json.dumps(rows, indent=2)


async def do_spawn_swarm(deps: CoordinatorDeps, finding_id: str) -> str:
    """Spawn a swarm of solvers to triage a single finding."""
    # STRATEGY: cost-aware early stopping
    budget = getattr(deps, "budget_usd", 10.0)
    if budget > 0 and deps.cost_tracker.total_cost_usd >= budget:
        msg = (
            f"Budget ${budget:.2f} reached "
            f"(spent ${deps.cost_tracker.total_cost_usd:.2f}) — "
            "not spawning new swarms."
        )
        logger.warning("STRATEGY: %s", msg)
        return msg

    # Retire finished swarms before checking capacity
    finished = [
        name for name, swarm in deps.swarms.items()
        if swarm.cancel_event.is_set()
        or (name in deps.swarm_tasks and deps.swarm_tasks[name].done())
    ]
    for name in finished:
        del deps.swarms[name]
        deps.swarm_tasks.pop(name, None)

    active_count = len(deps.swarms)
    if active_count >= deps.max_concurrent_findings:
        return f"At capacity ({active_count}/{deps.max_concurrent_findings} running). Wait for one to finish."

    if finding_id in deps.swarms:
        return f"Swarm still running for {finding_id}"

    if finding_id in deps.results:
        return f"Finding {finding_id} already triaged: {deps.results[finding_id].get('verdict', '?')}"

    # Find the SemgrepFinding object
    finding = next((f for f in deps.findings if f.finding_id == finding_id), None)
    if finding is None:
        return f"Finding '{finding_id}' not in findings list"

    from backend.agents.swarm import FindingSwarm

    swarm = FindingSwarm(
        finding=finding,
        target_dir=deps.target_dir,
        cost_tracker=deps.cost_tracker,
        settings=deps.settings,
        model_specs=deps.model_specs,
        coordinator_inbox=deps.coordinator_inbox,
    )
    deps.swarms[finding_id] = swarm

    async def _run_and_cleanup() -> None:
        result = await swarm.run()
        if result and result.status == TRIAGE_DONE and result.verdict:
            v = result.verdict
            deps.results[finding_id] = {
                "verdict": v.verdict,
                "confidence": v.confidence,
                "reasoning": v.reasoning,
                "exploitability": v.exploitability,
                "proof_of_concept": v.proof_of_concept,
                "remediation": v.remediation,
                "verdict_obj": v,
            }
            logger.info(
                "Triage complete for %s: %s (confidence=%.2f)",
                finding_id, v.verdict, v.confidence,
            )
        else:
            deps.results[finding_id] = {"verdict": "uncertain", "reasoning": "Solver did not return a verdict."}

    import asyncio
    task = asyncio.create_task(_run_and_cleanup(), name=f"swarm-{finding_id}")
    deps.swarm_tasks[finding_id] = task
    return f"Swarm spawned for {finding_id} ({finding.path}:{finding.line}) with {len(deps.model_specs)} model(s)"


async def do_kill_swarm(deps: CoordinatorDeps, finding_id: str) -> str:
    swarm = deps.swarms.get(finding_id)
    if not swarm:
        return f"No swarm running for {finding_id}"
    swarm.kill()
    return f"Swarm for {finding_id} cancelled"


async def do_bump_solver(
    deps: CoordinatorDeps, finding_id: str, model_spec: str, insights: str
) -> str:
    swarm = deps.swarms.get(finding_id)
    if not swarm:
        return f"No swarm running for {finding_id}"
    solver = swarm.solvers.get(model_spec)
    if not solver:
        return f"No solver for {model_spec} in {finding_id}"
    solver.bump(insights)
    return f"Bumped {model_spec} on {finding_id}"


async def do_read_solver_trace(
    deps: CoordinatorDeps, finding_id: str, model_spec: str, last_n: int = 20
) -> str:
    """Read the last N trace events from a solver's JSONL log."""
    swarm = deps.swarms.get(finding_id)
    if not swarm:
        return f"No swarm for {finding_id}"
    solver = swarm.solvers.get(model_spec)
    if not solver:
        return f"No solver for {model_spec}"
    trace_obj = getattr(solver, "tracer", None)
    if not trace_obj:
        return "No tracer on solver"
    path = trace_obj.path if hasattr(trace_obj, "path") else str(trace_obj)
    try:
        lines = Path(path).read_text().strip().split("\n")
        recent = lines[-last_n:]
        summary = []
        import json as _json
        for line in recent:
            try:
                d = _json.loads(line)
                t = d.get("type", "?")
                if t == "tool_call":
                    summary.append(f"step {d.get('step','?')} CALL {d.get('tool','?')}: {str(d.get('args',''))[:100]}")
                elif t == "tool_result":
                    summary.append(f"step {d.get('step','?')} RESULT {d.get('tool','?')}: {str(d.get('result',''))[:100]}")
                elif t in ("finish", "error", "bump", "triage_submitted"):
                    summary.append(f"** {t}: {_json.dumps({k:v for k,v in d.items() if k != 'ts'})}")
                elif t == "usage":
                    summary.append(f"usage: in={d.get('input_tokens',0)} out={d.get('output_tokens',0)} cost=${d.get('cost_usd',0):.4f}")
                else:
                    summary.append(f"{t}: {str(d)[:80]}")
            except Exception:
                summary.append(line[:100])
        return "\n".join(summary)
    except FileNotFoundError:
        return f"Trace file not found: {path}"
    except Exception as e:
        return f"Error reading trace: {e}"


async def do_broadcast(deps: CoordinatorDeps, finding_id: str, message: str) -> str:
    swarm = deps.swarms.get(finding_id)
    if not swarm:
        return f"No swarm running for {finding_id}"
    await swarm.message_bus.broadcast(message)
    return f"Broadcast to all solvers on {finding_id}"
