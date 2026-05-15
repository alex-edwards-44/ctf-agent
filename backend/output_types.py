"""Structured output types for solver agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from pydantic import BaseModel


@dataclass
class SemgrepFinding:
    """A single finding produced by Semgrep."""

    finding_id: str       # stable hash of rule_id + path + line
    path: str             # relative to target repo root
    line: int
    rule_id: str
    severity: str         # ERROR | WARNING | INFO
    message: str
    code_snippet: str
    cwe: str              # CWE tag or empty string


@dataclass
class ExploitResult:
    """Result from an ExploitSolver attempting to verify a vulnerability."""

    finding_id: str
    verified: bool
    exploit_type: str = ""       # e.g. "sqli", "xss", "rce", "auth-bypass"
    exploit_script: str = ""     # reproduce commands / code
    exploit_output: str = ""     # capped at 4 KB
    evidence: str = ""           # what proved success
    failure_reason: str = ""     # why verification failed (if not verified)
    cost_usd: float = 0.0


class TriageVerdict(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "likely", "uncertain", "false_positive"]
    confidence: float     # 0.0 to 1.0
    reasoning: str        # solver's explanation (2-4 sentences)
    exploitability: Literal["trivial", "moderate", "difficult", "n/a"]
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None


def solver_output_json_schema() -> dict:
    """JSON schema for solver structured output — submitted at end of triage turn."""
    return {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "likely", "uncertain", "false_positive"],
            },
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "reasoning": {"type": "string"},
            "exploitability": {
                "type": "string",
                "enum": ["trivial", "moderate", "difficult", "n/a"],
            },
            "proof_of_concept": {"type": ["string", "null"]},
            "remediation": {"type": ["string", "null"]},
        },
        "required": ["verdict", "confidence", "reasoning", "exploitability"],
        "additionalProperties": False,
    }
