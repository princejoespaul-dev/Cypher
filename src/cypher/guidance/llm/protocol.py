"""Provider-agnostic structured LLM client contract and result provenance."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class GenerationParams:
    temperature: float = 0.0
    max_output_tokens: int = 4_000
    seed: int = 0


@dataclass(frozen=True, slots=True)
class LLMResult:
    model_id: str
    output: dict[str, object]
    raw_text: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    provider_request_id: str | None = None


class LLMClient(Protocol):
    def estimate_cost_usd(self, input_tokens: int, output_tokens: int) -> float: ...
    def generate_structured(self, *, system: str, user: str, schema: dict[str, object], params: GenerationParams) -> LLMResult: ...
