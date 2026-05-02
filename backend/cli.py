"""vuln-triage CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings
from backend.models import DEFAULT_MODELS

console = Console()


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
              help="Custom Semgrep rules file or registry config (overrides auto)")
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
    no_cleanup: bool,
    msg_port: int,
) -> None:
    from backend.repo_loader import RepoLoader
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.scanner import run_semgrep

    settings = Settings(sandbox_image=image)
    settings.max_concurrent_findings = max_concurrent
    settings.max_solver_steps = max_solver_steps
    settings.budget_usd = budget_usd

    console.print("[bold]vuln-triage[/bold]")
    console.print(f"  Target:           {target}")
    console.print(f"  Models:           {', '.join(model_specs)}")
    console.print(f"  Max concurrent:   {max_concurrent}")
    console.print(f"  Max solver steps: {max_solver_steps if max_solver_steps > 0 else 'unlimited'}")
    console.print(f"  Budget:           {'$' + f'{budget_usd:.2f}' if budget_usd > 0 else 'unlimited'}")
    console.print(f"  Severity filter:  {severity}")
    console.print(f"  Output:           {output}")
    console.print()

    configure_semaphore(max_concurrent * len(model_specs))
    await cleanup_orphan_containers()

    loader = RepoLoader(target, no_cleanup=no_cleanup)
    local_path = loader._resolve()

    try:
        # Step 1: Run Semgrep
        console.print("[bold]Step 1: Running Semgrep...[/bold]")
        if semgrep_config:
            findings = run_semgrep(local_path, config=semgrep_config, severity_min=severity)
        else:
            findings = run_semgrep(local_path, config="auto", severity_min=severity)
            if not findings:
                console.print("[yellow]No findings from --config=auto. Retrying with --config=p/security-audit...[/yellow]")
                findings = run_semgrep(local_path, config="p/security-audit", severity_min=severity)

        if not findings:
            console.print("[yellow]No Semgrep findings. Nothing to triage.[/yellow]")
            _write_empty_report(output, target)
            return

        console.print(f"[green]Found {len(findings)} finding(s) to triage.[/green]\n")
        for i, f in enumerate(findings, 1):
            console.print(f"  [{i:3d}] {f.severity:7s}  {f.path}:{f.line}  ({f.rule_id})")
        console.print()

        # Step 2: Triage
        console.print("[bold]Step 2: Triaging findings...[/bold]\n")

        from backend.agents.claude_coordinator import run_claude_coordinator

        run_result = await run_claude_coordinator(
            settings=settings,
            findings=findings,
            target_dir=local_path,
            model_specs=model_specs,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
        )

        verdicts_raw = run_result.get("results", {})
        total_cost = run_result.get("total_cost_usd", 0.0)

        # Step 3: Generate report
        console.print("\n[bold]Step 3: Generating report...[/bold]")

        from backend.output_types import TriageVerdict
        from backend.report import generate_report

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

        report_md = generate_report(
            findings=findings,
            verdicts=verdicts,
            target=target,
            total_cost_usd=total_cost,
        )

        Path(output).write_text(report_md)
        console.print(f"[green]Report written to:[/green] {output}\n")

        # Summary
        from collections import Counter
        counts = Counter(v.verdict for v in verdicts.values())
        console.print("[bold]Triage Summary:[/bold]")
        console.print(f"  Confirmed:      {counts.get('confirmed', 0)}")
        console.print(f"  Likely:         {counts.get('likely', 0)}")
        console.print(f"  Uncertain:      {counts.get('uncertain', 0)}")
        console.print(f"  False positive: {counts.get('false_positive', 0)}")
        console.print(f"  Not triaged:    {len(findings) - len(verdicts)}")
        console.print(f"\n[bold]Total cost: ${total_cost:.2f}[/bold]")

    finally:
        loader.cleanup()


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
