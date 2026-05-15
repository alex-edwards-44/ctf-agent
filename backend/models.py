"""Model spec parsing — provider/model-id/effort resolution used by solver swarm."""

from __future__ import annotations

# Default model specs for vuln-triage
DEFAULT_MODELS: list[str] = [
    "claude-sdk/claude-opus-4-6/medium",
    "claude-sdk/claude-opus-4-6/max",
    "google/gemini-2.5-pro",
    "openai/gpt-5.4",
]


def model_id_from_spec(spec: str) -> str:
    """Extract just the model ID from a spec (strips provider prefix and effort suffix)."""
    parts = spec.split("/")
    return parts[1] if len(parts) >= 2 else spec


def provider_from_spec(spec: str) -> str:
    """Extract the provider from a spec like 'claude-sdk/claude-opus-4-6/max'."""
    return spec.split("/", 1)[0]


def effort_from_spec(spec: str) -> str | None:
    """Extract effort level from a spec like 'claude-sdk/claude-opus-4-6/max'."""
    parts = spec.split("/")
    if len(parts) >= 3 and parts[2] in ("low", "medium", "high", "max"):
        return parts[2]
    return None
