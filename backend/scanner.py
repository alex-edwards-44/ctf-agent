"""Semgrep runner — scans a target directory and returns structured findings."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
from pathlib import Path

from backend.output_types import SemgrepFinding

logger = logging.getLogger(__name__)

# Severity order for sorting (lower = higher priority)
SEVERITY_ORDER: dict[str, int] = {"ERROR": 0, "WARNING": 1, "INFO": 2}

SEVERITY_ALIASES: dict[str, str] = {
    "error": "ERROR",
    "warning": "WARNING",
    "info": "INFO",
    "all": "INFO",  # "all" means include everything down to INFO
}

# Default rule packs run when no --semgrep-config or --semgrep-rules is given
DEFAULT_PACKS: list[str] = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/secrets",
]

# OWASP Top 10 2021 CWE IDs — findings matching these rank higher in triage filtering
_OWASP_CWES: frozenset[str] = frozenset({
    "CWE-20", "CWE-22", "CWE-73", "CWE-74", "CWE-77", "CWE-78", "CWE-79",
    "CWE-89", "CWE-90", "CWE-94", "CWE-116", "CWE-200", "CWE-209",
    "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-311", "CWE-326",
    "CWE-327", "CWE-345", "CWE-346", "CWE-352", "CWE-384", "CWE-502",
    "CWE-611", "CWE-732", "CWE-798", "CWE-918",
})


def _cwe_id(cwe_str: str) -> str:
    """Extract canonical CWE ID (e.g. 'CWE-89') from a metadata CWE string."""
    m = re.match(r"(CWE-\d+)", cwe_str.strip(), re.IGNORECASE)
    return m.group(1).upper() if m else ""


def _extract_cwe(metadata: dict) -> str:
    """Pull the first CWE tag from Semgrep finding metadata."""
    cwe = metadata.get("cwe") or metadata.get("cwe2022-top25") or ""
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    return str(cwe)


def _make_finding_id(rule_id: str, path: str, line: int) -> str:
    raw = f"{rule_id}:{path}:{line}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _parse_semgrep_output(raw: dict, target_dir: str, severity_min: str) -> list[SemgrepFinding]:
    min_level = SEVERITY_ORDER.get(severity_min.upper(), 1)
    results = raw.get("results", [])
    findings: list[SemgrepFinding] = []

    for r in results:
        severity = (r.get("extra", {}).get("severity") or "WARNING").upper()
        if SEVERITY_ORDER.get(severity, 99) > min_level:
            continue

        path_abs = r.get("path", "")
        # Store relative path
        try:
            path_rel = str(Path(path_abs).relative_to(target_dir))
        except ValueError:
            path_rel = path_abs

        line = r.get("start", {}).get("line", 0)
        rule_id = r.get("check_id", "unknown")
        message = r.get("extra", {}).get("message", "")
        snippet = (r.get("extra", {}).get("lines") or "").strip()
        metadata = r.get("extra", {}).get("metadata") or {}
        cwe = _extract_cwe(metadata)
        finding_id = _make_finding_id(rule_id, path_rel, line)

        findings.append(SemgrepFinding(
            finding_id=finding_id,
            path=path_rel,
            line=line,
            rule_id=rule_id,
            severity=severity,
            message=message,
            code_snippet=snippet[:2000],
            cwe=cwe,
        ))

    return findings


def _sort_findings(findings: list[SemgrepFinding]) -> list[SemgrepFinding]:
    """Sort by severity (ERROR first), then by CWE presence, then path."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            0 if f.cwe else 1,
            f.path,
            f.line,
        ),
    )


def run_semgrep(
    target_dir: str,
    config: str = "auto",
    severity_min: str = "warning",
) -> list[SemgrepFinding]:
    """Run Semgrep on target_dir and return sorted findings.

    Returns an empty list on scan error (caller decides whether to retry with
    a different config).
    """
    cmd = [
        "semgrep",
        "--config", config,
        "--json",
        "--no-git-ignore",
        target_dir,
    ]
    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after 300s")
        return []
    except FileNotFoundError:
        logger.error("semgrep not found — install via: brew install semgrep")
        return []

    if proc.returncode not in (0, 1):  # 0 = ok, 1 = findings found
        logger.error("Semgrep exited %d:\n%s", proc.returncode, proc.stderr[:500])
        return []

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Semgrep JSON output: %s", e)
        return []

    findings = _parse_semgrep_output(raw, target_dir, severity_min)
    findings = _sort_findings(findings)

    errors = raw.get("errors", [])
    if errors:
        logger.warning("Semgrep reported %d parse error(s) (non-fatal)", len(errors))

    logger.info(
        "Semgrep found %d finding(s) at or above %s severity",
        len(findings), severity_min.upper(),
    )
    return findings


def _dedup_findings(findings: list[SemgrepFinding]) -> list[SemgrepFinding]:
    seen: set[tuple[str, int, str]] = set()
    out: list[SemgrepFinding] = []
    for f in findings:
        key = (f.path, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def run_semgrep_multi(
    target_dir: str,
    configs: list[str] | None = None,
    severity_min: str = "warning",
) -> list[SemgrepFinding]:
    """Run Semgrep with multiple rule packs and return deduplicated, sorted findings."""
    packs = configs if configs is not None else DEFAULT_PACKS
    all_findings: list[SemgrepFinding] = []
    for pack in packs:
        found = run_semgrep(target_dir, config=pack, severity_min=severity_min)
        all_findings.extend(found)
    deduped = _sort_findings(_dedup_findings(all_findings))
    logger.info(
        "Multi-pack scan: %d unique finding(s) from %d pack(s)",
        len(deduped), len(packs),
    )
    return deduped


def filter_findings(
    findings: list[SemgrepFinding],
    top_percent: float = 100.0,
    threshold: int = 100,
    target_dir: str = "",
) -> tuple[list[SemgrepFinding], list[SemgrepFinding]]:
    """Return (to_triage, skipped).

    Filtering activates when len(findings) > threshold AND top_percent < 100.
    Prioritisation: ERROR > WARNING > INFO, then OWASP CWEs first, then smaller files first.
    """
    n = len(findings)
    if top_percent >= 100.0 or n <= threshold:
        return findings, []

    keep_n = max(1, int(n * top_percent / 100.0))

    def _score(f: SemgrepFinding) -> tuple:
        sev = SEVERITY_ORDER.get(f.severity, 99)
        is_owasp = 0 if _cwe_id(f.cwe) in _OWASP_CWES else 1
        fsize = 0
        if target_dir:
            try:
                fsize = Path(target_dir, f.path).stat().st_size
            except OSError:
                pass
        return (sev, is_owasp, fsize)

    prioritized = sorted(findings, key=_score)
    logger.info(
        "Triage filter active: keeping %d/%d findings (top %.0f%% of %d > threshold %d)",
        keep_n, n, top_percent, n, threshold,
    )
    return prioritized[:keep_n], prioritized[keep_n:]
