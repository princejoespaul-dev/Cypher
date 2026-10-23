"""Deterministic fake LLM adapter for tests, CI, and recorded-output replay."""
from __future__ import annotations

import json
from collections import deque
from typing import Any

from cypher.core.canonical import canonical_json_bytes
from cypher.guidance.llm.protocol import GenerationParams, LLMResult


class FakeLLMClient:
    def __init__(self, outputs: list[dict[str, Any]] | None = None, *, model_id: str = "fake-structured-1") -> None:
        self._outputs = deque(outputs or [])
        self.model_id = model_id
        self.calls: list[dict[str, object]] = []

    def estimate_cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        return 0.0

    def generate_structured(self, *, system: str, user: str, schema: dict[str, object], params: GenerationParams) -> LLMResult:
        self.calls.append({"system": system, "user": user, "schema": schema, "params": params.__dict__ if hasattr(params, "__dict__") else {"temperature": params.temperature, "max_output_tokens": params.max_output_tokens, "seed": params.seed}})
        output = self._outputs.popleft() if self._outputs else {"capsules": []}
        raw = canonical_json_bytes(output, permit_float=True).decode("utf-8")
        return LLMResult(self.model_id, output, raw, max(1, len(user) // 4), max(1, len(raw) // 4), 0.0, f"fake-{len(self.calls)}")
