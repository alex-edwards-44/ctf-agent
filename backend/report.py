"""Render triage results as a Markdown report."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.output_types import SemgrepFinding, TriageVerdict

# Verdict ordering for report sections
VERDICT_ORDER = ["confirmed", "likely", "uncertain", "false_positive"]

SECTION_TITLES = {
    "confirmed": "Confirmed Vulnerabilities",
    "likely": "Likely Vulnerabilities",
    "uncertain": "Uncertain",
    "false_positive": "False Positives",
}

SEVERITY_EMOJI = {
    "ERROR": "🔴",
    "WARNING": "🟡",
    "INFO": "🔵",
}

EXPLOITABILITY_EMOJI = {
    "trivial": "🔥",
    "moderate": "⚠️",
    "difficult": "🔒",
    "n/a": "—",
}


def _finding_header(finding: "SemgrepFinding", verdict: "TriageVerdict") -> str:
    sev_icon = SEVERITY_EMOJI.get(finding.severity, "⚪")
    exp_icon = EXPLOITABILITY_EMOJI.get(verdict.exploitability, "")
    cwe = f" · {finding.cwe}" if finding.cwe else ""
    return (
        f"### {sev_icon} `{finding.path}:{finding.line}`{cwe}\n\n"
        f"**Rule**: `{finding.rule_id}`  \n"
        f"**Severity**: {finding.severity}  \n"
        f"**Exploitability**: {exp_icon} {verdict.exploitability}  \n"
        f"**Confidence**: {verdict.confidence:.0%}"
    )


def _finding_body(finding: "SemgrepFinding", verdict: "TriageVerdict") -> str:
    parts: list[str] = []

    parts.append(f"\n\n**Semgrep message**: {finding.message}")

    if finding.code_snippet:
        parts.append(f"\n\n**Flagged code**:\n```\n{finding.code_snippet}\n```")

    parts.append(f"\n\n**Verdict**: {verdict.reasoning}")

    if verdict.proof_of_concept:
        parts.append(f"\n\n**Proof of concept**:\n```\n{verdict.proof_of_concept}\n```")

    if verdict.remediation:
        parts.append(f"\n\n**Remediation**: {verdict.remediation}")

    return "".join(parts)


def generate_report(
    findings: list["SemgrepFinding"],
    verdicts: dict[str, "TriageVerdict"],
    target: str = "",
    total_cost_usd: float = 0.0,
) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build lookup map
    finding_map = {f.finding_id: f for f in findings}

    # Group by verdict
    by_verdict: dict[str, list[tuple["SemgrepFinding", "TriageVerdict"]]] = {
        v: [] for v in VERDICT_ORDER
    }
    untriaged: list["SemgrepFinding"] = []

    for finding in findings:
        verdict = verdicts.get(finding.finding_id)
        if verdict:
            by_verdict[verdict.verdict].append((finding, verdict))
        else:
            untriaged.append(finding)

    # Summary counts
    confirmed = len(by_verdict["confirmed"])
    likely = len(by_verdict["likely"])
    uncertain = len(by_verdict["uncertain"])
    fp = len(by_verdict["false_positive"])
    total = len(findings)
    triaged = total - len(untriaged)

    lines: list[str] = [
        "# Vulnerability Triage Report",
        "",
        f"**Generated**: {now}  ",
        f"**Target**: `{target or 'unknown'}`  ",
        f"**Total cost**: ${total_cost_usd:.2f}",
        "",
        "## Summary",
        "",
        f"| Category | Count |",
        f"|----------|-------|",
        f"| 🔴 Confirmed | {confirmed} |",
        f"| 🟡 Likely | {likely} |",
        f"| ❓ Uncertain | {uncertain} |",
        f"| ✅ False Positive | {fp} |",
        f"| ⏭ Not triaged | {len(untriaged)} |",
        f"| **Total** | **{total}** |",
        "",
    ]

    # Sections
    for verdict_key in VERDICT_ORDER:
        entries = by_verdict[verdict_key]
        if not entries:
            continue

        title = SECTION_TITLES[verdict_key]
        lines.append(f"## {title} ({len(entries)})")
        lines.append("")

        for finding, verdict in entries:
            lines.append(_finding_header(finding, verdict))
            lines.append(_finding_body(finding, verdict))
            lines.append("")
            lines.append("---")
            lines.append("")

    # Untriaged
    if untriaged:
        lines.append(f"## Not Triaged ({len(untriaged)})")
        lines.append("")
        lines.append("These findings were not reached due to budget or concurrency limits.")
        lines.append("")
        for f in untriaged:
            sev_icon = SEVERITY_EMOJI.get(f.severity, "⚪")
            cwe = f" · {f.cwe}" if f.cwe else ""
            lines.append(f"- {sev_icon} `{f.path}:{f.line}` — `{f.rule_id}`{cwe}")
        lines.append("")

    return "\n".join(lines)
