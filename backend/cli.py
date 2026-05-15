"""vuln-triage CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import math
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings
from backend.models import DEFAULT_MODELS

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiodocker").setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%X")
    )
    logging.basicConfig(level=level, handlers=[handler], force=True)


@click.command()
@click.argument("target", metavar="<github-url-or-local-path>")
@click.option("--max-concurrent", default=4, type=int, show_default=True,
              help="Max findings triaged in parallel")
@click.option("--max-solver-steps", default=30, type=int, show_default=True,
              help="Per-solver tool-call cap (0 = unlimited)")
@click.option("--budget-usd", default=10.0, type=float, show_default=True,
              help="Total API cost ceiling in USD (0 = unlimited)")
@click.option("--severity", default="warning",
              type=click.Choice(["error", "warning", "info", "all"], case_sensitive=False),
              show_default=True, help="Minimum Semgrep severity to triage")
@click.option("--output", default="report.md", show_default=True,
              help="Output path for the markdown report")
@click.option("--image", default="vuln-sandbox", show_default=True,
              help="Docker sandbox image name")
@click.option("--models", multiple=True,
              help="Model specs (repeatable; default: all configured)")
@click.option("--coordinator-model", default=None,
              help="Model for coordinator (default: claude-opus-4-6)")
@click.option("--semgrep-config", default=None,
              help="Custom Semgrep rules file or registry config (overrides default multi-pack scan)")
@click.option("--semgrep-rules", default=None,
              help="Comma-separated Semgrep rule packs to run (e.g. 'p/security-audit,p/owasp-top-ten')")
@click.option("--triage-top-percent", default=100.0, type=float, show_default=True,
              help="Triage only top N%% of findings when count exceeds --triage-threshold")
@click.option("--triage-threshold", default=100, type=int, show_default=True,
              help="Finding count above which --triage-top-percent activates")
@click.option("--exploit-mode", default="none",
              type=click.Choice(["none", "suggest", "verify"], case_sensitive=False),
              show_default=True, help="Exploit verification mode")
@click.option("--exploit-top-n", default=0, type=int, show_default=True,
              help="Number of confirmed findings to attempt exploitation (0 = auto: 10%% of confirmed, min 3, max 10)")
@click.option("--exploit-timeout-seconds", default=300, type=int, show_default=True,
              help="Seconds per exploit attempt")
@click.option("--exploit-budget-usd", default=5.0, type=float, show_default=True,
              help="Max USD to spend on exploit verification phase")
@click.option("--no-cleanup", is_flag=True,
              help="Don't delete the cloned repo at end (for debugging)")
@click.option("--msg-port", default=0, type=int,
              help="Operator message port (0 = auto)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(
    target: str,
    max_concurrent: int,
    max_solver_steps: int,
    budget_usd: float,
    severity: str,
    output: str,
    image: str,
    models: tuple[str, ...],
    coordinator_model: str | None,
    semgrep_config: str | None,
    semgrep_rules: str | None,
    triage_top_percent: float,
    triage_threshold: int,
    exploit_mode: str,
    exploit_top_n: int,
    exploit_timeout_seconds: int,
    exploit_budget_usd: float,
    no_cleanup: bool,
    msg_port: int,
    verbose: bool,
) -> None:
    """vuln-triage — Semgrep-driven vulnerability triage with a multi-model solver swarm."""
    _setup_logging(verbose)
    asyncio.run(
        _run(
            target=target,
            max_concurrent=max_concurrent,
            max_solver_steps=max_solver_steps,
            budget_usd=budget_usd,
            severity=severity,
            output=output,
            image=image,
            model_specs=list(models) if models else list(DEFAULT_MODELS),
            coordinator_model=coordinator_model,
            semgrep_config=semgrep_config,
            semgrep_rules=semgrep_rules,
            triage_top_percent=triage_top_percent,
            triage_threshold=triage_threshold,
            exploit_mode=exploit_mode,
            exploit_top_n=exploit_top_n,
            exploit_timeout_seconds=exploit_timeout_seconds,
            exploit_budget_usd=exploit_budget_usd,
            no_cleanup=no_cleanup,
            msg_port=msg_port,
        )
    )


async def _run(
    target: str,
    max_concurrent: int,
    max_solver_steps: int,
    budget_usd: float,
    severity: str,
    output: str,
    image: str,
    model_specs: list[str],
    coordinator_model: str | None,
    semgrep_config: str | None,
    semgrep_rules: str | None,
    triage_top_percent: float,
    triage_threshold: int,
    exploit_mode: str,
    exploit_top_n: int,
    exploit_timeout_seconds: int,
    exploit_budget_usd: float,
    no_cleanup: bool,
    msg_port: int,
) -> None:
    from backend.repo_loader import RepoLoader
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.scanner import DEFAULT_PACKS, filter_findings, run_semgrep, run_semgrep_multi

    settings = Settings(sandbox_image=image)
    settings.max_concurrent_findings = max_concurrent
    settings.max_solver_steps = max_solver_steps
    settings.budget_usd = budget_usd

    # Determine which packs will be used (for display and scanning)
    if semgrep_config:
        active_packs: list[str] | None = None
        packs_display = f"custom config: {semgrep_config}"
    elif semgrep_rules:
        active_packs = [p.strip() for p in semgrep_rules.split(",") if p.strip()]
        packs_display = ", ".join(active_packs)
    else:
        active_packs = None  # run_semgrep_multi defaults to DEFAULT_PACKS
        packs_display = ", ".join(DEFAULT_PACKS)

    console.print("[bold]vuln-triage[/bold]")
    console.print(f"  Target:           {target}")
    console.print(f"  Models:           {', '.join(model_specs)}")
    console.print(f"  Max concurrent:   {max_concurrent}")
    console.print(f"  Max solver steps: {max_solver_steps if max_solver_steps > 0 else 'unlimited'}")
    console.print(f"  Budget:           {'$' + f'{budget_usd:.2f}' if budget_usd > 0 else 'unlimited'}")
    console.print(f"  Severity filter:  {severity}")
    console.print(f"  Semgrep packs:    {packs_display}")
    if exploit_mode != "none":
        console.print(f"  Exploit mode:     {exploit_mode} (budget: ${exploit_budget_usd:.2f})")
    console.print(f"  Output:           {output}")
    console.print()

    configure_semaphore(max_concurrent * len(model_specs))
    await cleanup_orphan_containers()

    loader = RepoLoader(target, no_cleanup=no_cleanup)
    local_path = loader._resolve()

    try:
        # Step 1: Run Semgrep (multi-pack by default)
        console.print("[bold]Step 1: Running Semgrep...[/bold]")
        if semgrep_config:
            findings = run_semgrep(local_path, config=semgrep_config, severity_min=severity)
        else:
            findings = run_semgrep_multi(local_path, configs=active_packs, severity_min=severity)

        if not findings:
            console.print("[yellow]No Semgrep findings. Nothing to triage.[/yellow]")
            _write_empty_report(output, target)
            return

        console.print(f"[green]Found {len(findings)} finding(s).[/green]")
        for i, f in enumerate(findings, 1):
            console.print(f"  [{i:3d}] {f.severity:7s}  {f.path}:{f.line}  ({f.rule_id})")
        console.print()

        # Step 2: Apply triage size filter
        to_triage, skipped = filter_findings(
            findings,
            top_percent=triage_top_percent,
            threshold=triage_threshold,
            target_dir=local_path,
        )
        if skipped:
            console.print(
                f"[yellow]Filtering: triaging top {triage_top_percent:.0f}% of "
                f"{len(findings)} findings = {len(to_triage)}. "
                f"Skipping {len(skipped)} lower-severity findings.[/yellow]\n"
            )

        # Step 3: Triage
        console.print(f"[bold]Step 2: Triaging {len(to_triage)} finding(s)...[/bold]\n")

        from backend.agents.claude_coordinator import run_claude_coordinator

        run_result = await run_claude_coordinator(
            settings=settings,
            findings=to_triage,
            target_dir=local_path,
            model_specs=model_specs,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
        )

        verdicts_raw = run_result.get("results", {})
        total_cost = run_result.get("total_cost_usd", 0.0)

        from backend.output_types import TriageVerdict

        verdicts: dict[str, TriageVerdict] = {}
        for fid, data in verdicts_raw.items():
            v = data.get("verdict_obj")
            if isinstance(v, TriageVerdict):
                verdicts[fid] = v
            elif isinstance(data, dict) and "verdict" in data:
                try:
                    verdicts[fid] = TriageVerdict(
                        finding_id=fid,
                        verdict=data["verdict"],
                        confidence=data.get("confidence", 0.5),
                        reasoning=data.get("reasoning", ""),
                        exploitability=data.get("exploitability", "n/a"),
                        proof_of_concept=data.get("proof_of_concept"),
                        remediation=data.get("remediation"),
                    )
                except Exception:
                    pass

        # Step 4: Exploit phase (optional)
        exploit_results: dict = {}
        if exploit_mode != "none":
            findings_map = {f.finding_id: f for f in to_triage}
            exploit_results, exploit_cost = await _run_exploit_phase(
                verdicts=verdicts,
                findings_map=findings_map,
                target_dir=local_path,
                settings=settings,
                exploit_mode=exploit_mode,
                exploit_top_n=exploit_top_n,
                exploit_timeout_seconds=exploit_timeout_seconds,
                exploit_budget_usd=exploit_budget_usd,
            )
            total_cost += exploit_cost

        # Step 5: Generate report
        step_num = 5 if exploit_mode != "none" else 3
        console.print(f"\n[bold]Step {step_num}: Generating report...[/bold]")

        from backend.report import generate_report

        report_md = generate_report(
            findings=to_triage,
            verdicts=verdicts,
            target=target,
            total_cost_usd=total_cost,
            skipped_findings=skipped or None,
            exploit_results=exploit_results or None,
        )

        Path(output).write_text(report_md)
        console.print(f"[green]Report written to:[/green] {output}\n")

        from collections import Counter
        counts = Counter(v.verdict for v in verdicts.values())
        console.print("[bold]Triage Summary:[/bold]")
        console.print(f"  Confirmed:      {counts.get('confirmed', 0)}")
        console.print(f"  Likely:         {counts.get('likely', 0)}")
        console.print(f"  Uncertain:      {counts.get('uncertain', 0)}")
        console.print(f"  False positive: {counts.get('false_positive', 0)}")
        console.print(f"  Not triaged:    {len(to_triage) - len(verdicts)}")
        if skipped:
            console.print(f"  Filtered out:   {len(skipped)}")
        if exploit_results:
            verified_n = sum(1 for r in exploit_results.values() if r.verified)
            console.print(f"  Verified exploits: {verified_n}/{len(exploit_results)}")
        console.print(f"\n[bold]Total cost: ${total_cost:.2f}[/bold]")

    finally:
        loader.cleanup()


async def _run_exploit_phase(
    verdicts: dict,
    findings_map: dict,
    target_dir: str,
    settings: Settings,
    exploit_mode: str,
    exploit_top_n: int,
    exploit_timeout_seconds: int,
    exploit_budget_usd: float,
) -> tuple[dict, float]:
    """Run exploit verification on top confirmed findings. Returns (exploit_results, total_cost)."""
    from backend.cost_tracker import CostTracker
    from backend.output_types import ExploitResult
    from backend.scanner import SEVERITY_ORDER

    confirmed = [v for v in verdicts.values() if v.verdict == "confirmed"]
    if not confirmed:
        console.print("[yellow]Exploit phase: no confirmed findings to exploit.[/yellow]")
        return {}, 0.0

    def _rank(v):
        f = findings_map.get(v.finding_id)
        sev = SEVERITY_ORDER.get(f.severity if f else "WARNING", 99)
        has_cwe = 0 if (f and f.cwe) else 1
        return (sev, has_cwe)

    confirmed.sort(key=_rank)

    num_confirmed = len(confirmed)
    if exploit_top_n <= 0:
        n = max(3, min(10, math.ceil(0.10 * num_confirmed))) if num_confirmed >= 3 else num_confirmed
    else:
        n = exploit_top_n
    top_verdicts = confirmed[:n]

    console.print(
        f"\n[bold]Step 4: Exploit phase ({exploit_mode}) — "
        f"top {n} of {num_confirmed} confirmed finding(s)...[/bold]\n"
    )

    cost_tracker = CostTracker()
    exploit_results: dict[str, ExploitResult] = {}
    exploit_spend = 0.0

    for verdict in top_verdicts:
        finding = findings_map.get(verdict.finding_id)
        if not finding:
            continue

        if exploit_budget_usd > 0 and exploit_spend >= exploit_budget_usd:
            console.print(
                f"[yellow]Exploit budget ${exploit_budget_usd:.2f} reached — "
                "stopping exploit phase.[/yellow]"
            )
            break

        console.print(f"  Exploiting: {finding.path}:{finding.line}  ({finding.rule_id})")

        if exploit_mode == "suggest":
            result = ExploitResult(
                finding_id=finding.finding_id,
                verified=False,
                exploit_type="suggested",
                exploit_script=verdict.proof_of_concept or "",
                failure_reason="suggest mode — PoC generated by triage, not executed",
                cost_usd=0.0,
            )
        else:
            from backend.agents.exploit_solver import ExploitSolver
            solver = ExploitSolver(
                finding=finding,
                verdict=verdict,
                target_dir=target_dir,
                cost_tracker=cost_tracker,
                settings=settings,
                timeout_seconds=exploit_timeout_seconds,
            )
            try:
                result = await solver.run()
            except Exception as exc:
                logger.error("ExploitSolver failed for %s: %s", finding.finding_id, exc)
                result = ExploitResult(
                    finding_id=finding.finding_id,
                    verified=False,
                    failure_reason=f"solver exception: {exc}",
                    cost_usd=0.0,
                )

        exploit_results[finding.finding_id] = result
        exploit_spend += result.cost_usd
        status = (
            "verified ✓"
            if result.verified
            else f"not verified ({(result.failure_reason or '')[:60]})"
        )
        console.print(f"    → {status}  (cost: ${result.cost_usd:.4f})")

    verified_n = sum(1 for r in exploit_results.values() if r.verified)
    console.print(
        f"\n  Exploit phase complete: {verified_n}/{len(exploit_results)} verified "
        f"(cost: ${cost_tracker.total_cost_usd:.2f})\n"
    )
    return exploit_results, cost_tracker.total_cost_usd


def _write_empty_report(output: str, target: str) -> None:
    from backend.report import generate_report
    report = generate_report(findings=[], verdicts={}, target=target, total_cost_usd=0.0)
    Path(output).write_text(report)
    console.print(f"Empty report written to: {output}")


@click.command()
@click.argument("message")
@click.option("--port", default=9400, type=int, help="Coordinator message port")
@click.option("--host", default="127.0.0.1", help="Coordinator host")
def msg(message: str, port: int, host: str) -> None:
    """Send a message to the running coordinator."""
    import json
    import urllib.request

    body = json.dumps({"message": message}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/msg",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            console.print(f"[green]Sent:[/green] {data.get('queued', message[:200])}")
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
