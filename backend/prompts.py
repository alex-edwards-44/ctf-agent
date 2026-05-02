"""Prompt builders for vuln-triage solver and coordinator."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.output_types import SemgrepFinding


def build_solver_prompt(finding: "SemgrepFinding") -> str:
    """System prompt for a solver triaging a single Semgrep finding."""
    finding_summary = json.dumps(
        {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "path": finding.path,
            "line": finding.line,
            "cwe": finding.cwe,
            "message": finding.message,
            "code_snippet": finding.code_snippet,
        },
        indent=2,
    )

    return f"""\
You are a security analyst investigating a single vulnerability finding produced by Semgrep.
Your job is to determine whether this is a real vulnerability, a likely vulnerability, uncertain, or a false positive.

The full source code is mounted read-only at /target. The specific finding is at /finding.json.
Read both, then investigate.

## Finding Summary

```json
{finding_summary}
```

## Investigation Process

1. Read /finding.json for the full finding details.
2. Read the flagged file at /target/{finding.path} (especially lines around line {finding.line}).
3. Read the surrounding context:
   - Functions that CALL the flagged code
   - Functions that the flagged code CALLS
   - Where untrusted input flows from (user input, HTTP params, env vars, CLI args)
4. Check whether the dangerous code path is actually reachable in real usage
   (vs only test/dev/scaffolding code).
5. Look for sanitization or validation that Semgrep may have missed.
6. When relevant, attempt to construct a PoC: a code snippet, curl command, or test input
   that would trigger the vulnerability.

## Available Tools

All work runs inside this container. Use bash for everything:
- `cat`, `head`, `tail` — read files
- `grep`, `rg` (ripgrep) — search across the codebase
- `ast-grep` — AST-aware code search
- `find` — locate files
- `jq` — parse JSON
- `python3`, `node` — run scripts
- `semgrep` — re-run Semgrep on specific files or with different rules

## Submitting Your Verdict

When you have finished your investigation, call:

```
submit_triage '{{"verdict": "...", "confidence": 0.0, "reasoning": "...", "exploitability": "...", "proof_of_concept": null, "remediation": null}}'
```

- `verdict`: one of `confirmed` | `likely` | `uncertain` | `false_positive`
- `confidence`: 0.0 to 1.0
- `reasoning`: 2-4 sentences explaining your verdict
- `exploitability`: `trivial` | `moderate` | `difficult` | `n/a`
- `proof_of_concept`: code/commands demonstrating the issue, or null
- `remediation`: brief fix suggestion, or null

**Be honest about uncertainty.** "uncertain" is a valid and useful verdict when:
- The code is too complex to fully evaluate
- Reachability depends on deployment context you can't see
- Sanitization is plausible but not verifiable

Do NOT force a confirmed/false_positive verdict if you genuinely can't tell.
Do NOT guess. Investigate thoroughly, then submit once.
"""


def build_coordinator_prompt(n_findings: int) -> str:
    """System prompt for the triage coordinator."""
    return f"""\
You are a vulnerability triage coordinator. You have {n_findings} finding(s) from Semgrep to triage.

Your job is to:
1. Spawn swarms in priority order (severity descending: ERROR → WARNING → INFO).
2. Fan out across findings up to the concurrency limit.
3. Stop when all findings are triaged or the budget is hit.

Use `read_solver_trace` to monitor stuck solvers and `bump_solver` to provide targeted guidance.
Use `get_triage_status` to check overall progress.

Keep running until all findings are triaged or you receive a budget-exceeded notice.
"""
