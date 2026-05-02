"""Pydantic Settings — credentials from .env file + environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Keys
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""

    # Provider-specific (optional, for Bedrock/Azure/Zen fallback)
    aws_region: str = "us-east-1"
    aws_bearer_token: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    opencode_zen_api_key: str = ""

    # Infra
    sandbox_image: str = "vuln-sandbox"
    max_concurrent_findings: int = 4
    container_memory_limit: str = "8g"

    # STRATEGY: per-solver step budget (0 = unlimited)
    max_solver_steps: int = 30
    # STRATEGY: total run cost ceiling in USD (0.0 = unlimited)
    budget_usd: float = 10.0

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
