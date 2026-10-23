"""Minimal OpenAI-compatible JSON-schema adapter using httpx, with no model tools enabled."""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from cypher.guidance.llm.protocol import GenerationParams, LLMResult


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfig:
    base_url: str
    api_key: str
    model_id: str
    timeout_seconds: float = 30.0
    input_cost_per_million_usd: float = 0.0
    output_cost_per_million_usd: float = 0.0

    def validate(self) -> None:
        parsed = urlsplit(self.base_url)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("LLM base_url must be a fixed origin without credentials, query or fragment")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("LLM provider URL must use HTTPS unless it is explicitly local")
        if not self.api_key or len(self.api_key) < 8:
            raise ValueError("LLM API key is missing")
        if not self.model_id:
            raise ValueError("LLM model id is required")
        if self.input_cost_per_million_usd < 0 or self.output_cost_per_million_usd < 0:
            raise ValueError("LLM token pricing cannot be negative")
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and self.input_cost_per_million_usd + self.output_cost_per_million_usd <= 0:
            raise ValueError("Configure provider token prices to enforce the project cost budget")


class OpenAICompatibleClient:
    """Use only the configured provider URL; generated output has no tools/functions."""
    def __init__(self, config: OpenAICompatibleConfig, *, client: httpx.Client | None = None) -> None:
        config.validate()
        self._config = config
        self._client = client or httpx.Client(timeout=config.timeout_seconds, follow_redirects=False, trust_env=False)
        self._owns_client = client is None

    def estimate_cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self._config.input_cost_per_million_usd + output_tokens * self._config.output_cost_per_million_usd) / 1_000_000

    def generate_structured(self, *, system: str, user: str, schema: dict[str, object], params: GenerationParams) -> LLMResult:
        body = {
            "model": self._config.model_id,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": params.temperature,
            "max_tokens": params.max_output_tokens,
            "seed": params.seed,
            "response_format": {"type": "json_schema", "json_schema": {"name": "cypher_structured_output", "strict": True, "schema": schema}},
        }
        response = self._client.post(self._config.base_url.rstrip("/") + "/chat/completions",
                                     headers={"Authorization": f"Bearer {self._config.api_key}", "Content-Type": "application/json"}, json=body)
        response.raise_for_status()
        envelope = response.json()
        choices = envelope.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("LLM response did not contain a choice")
        message = choices[0].get("message", {})
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ValueError("LLM response contained no structured content")
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("Structured LLM output must be a JSON object")
        usage = envelope.get("usage", {})
        input_tokens = int(usage.get("prompt_tokens", 0))
        output_tokens = int(usage.get("completion_tokens", 0))
        cost = self.estimate_cost_usd(input_tokens, output_tokens)
        return LLMResult(str(envelope.get("model", self._config.model_id)), parsed, content,
                         input_tokens, output_tokens, cost, str(envelope.get("id", uuid4())))

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
