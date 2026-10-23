"""Environment-based configuration with safe development defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str = "development"
    service_name: str = "cypher-api"
    api_key: str = "dev-only-change-me"
    database_url: str = "postgresql+psycopg://cypher:cypher-local-only@localhost:5432/cypher"
    redis_url: str = "redis://localhost:6379/0"
    evidence_dir: Path = Path(".cypher/evidence")
    sandbox_subnets: tuple[str, ...] = ("172.28.0.0/16", "172.30.0.0/24")
    request_timeout_seconds: float = 8.0
    max_repeats: int = 5
    max_body_bytes: int = 1_048_576
    guidance_daily_token_cap: int = 100_000
    guidance_daily_cost_cap_usd: float = 5.0
    guidance_enabled: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.getenv("CYPHER_ENV", "development").strip().lower()
        key = os.getenv("CYPHER_API_KEY", "dev-only-change-me")
        if env in {"production", "prod"} and (key == "dev-only-change-me" or len(key) < 32):
            raise ValueError("CYPHER_API_KEY must be at least 32 characters in production")
        subnets = tuple(x.strip() for x in os.getenv("CYPHER_SANDBOX_SUBNETS", "172.28.0.0/16,172.30.0.0/24").split(",") if x.strip())
        return cls(
            environment=env,
            api_key=key,
            database_url=os.getenv("CYPHER_DATABASE_URL", "postgresql+psycopg://cypher:cypher-local-only@localhost:5432/cypher"),
            redis_url=os.getenv("CYPHER_REDIS_URL", "redis://localhost:6379/0"),
            evidence_dir=Path(os.getenv("CYPHER_EVIDENCE_DIR", ".cypher/evidence")),
            sandbox_subnets=subnets,
            request_timeout_seconds=float(os.getenv("CYPHER_REQUEST_TIMEOUT_SECONDS", "8")),
            max_repeats=int(os.getenv("CYPHER_MAX_REPEATS", "5")),
            max_body_bytes=int(os.getenv("CYPHER_MAX_BODY_BYTES", "1048576")),
            guidance_daily_token_cap=int(os.getenv("CYPHER_GUIDANCE_DAILY_TOKEN_CAP", "100000")),
            guidance_daily_cost_cap_usd=float(os.getenv("CYPHER_GUIDANCE_DAILY_COST_CAP_USD", "5.0")),
            guidance_enabled=os.getenv("CYPHER_GUIDANCE_ENABLED", "false").lower() == "true",
        )

    @property
    def is_production(self) -> bool:
        return self.environment in {"production", "prod"}
