"""Explanation generation from stored evidence; server-side citations are mandatory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.core.errors import Invalid, NotFound
from cypher.guidance.explain import ExplanationRecord, validate_explanation
from cypher.guidance.llm.protocol import GenerationParams, LLMClient
from cypher.harness.phase5_models import Actor, EvidenceBundle, Role
from cypher.harness.phase5_ports import Phase5Repository


class ExplanationService:
    def __init__(self, *, repository: Phase5Repository, llm: LLMClient) -> None:
        self._repository = repository
        self._llm = llm

    def explain_verdict(self, *, verdict_id: UUID, actor: Actor) -> ExplanationRecord:
        if actor.role not in {Role.ADMIN, Role.ANALYST, Role.REVIEWER, Role.VIEWER}:
            raise Invalid("Role is not permitted to read verdict explanations")
        verdict = self._repository.get_verdict(verdict_id, actor.project_id)
        if verdict is None:
            raise NotFound("Verdict not found", code="verdict.not_found")
        evidence = self._repository.get_evidence_bundle(verdict.run_id, actor.project_id)
        if evidence is None:
            raise Invalid("Redacted evidence bundle is not available", code="evidence.missing")
        evidence_rows: list[dict[str, Any]] = []
        evidence_ids: set[str] = set()
        for index, row in enumerate(evidence.observations):
            evidence_id = sha256_hex(canonical_json_bytes(row, permit_float=True))
            evidence_ids.add(evidence_id)
            evidence_rows.append({"evidence_id": evidence_id, "observation_index": index, "observation": row})
        system_path = Path(__file__).parent / "prompts" / "explanation_v1.txt"
        system = system_path.read_text(encoding="utf-8")
        prompt_data = {"verdict_id": str(verdict.verdict_id), "stored_verdict": verdict.verdict.value,
                       "fired_rules": list(verdict.fired_rules), "signals": verdict.signals,
                       "redacted_evidence": evidence_rows}
        user = json.dumps(prompt_data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        schema = {"type": "object", "required": ["verdict", "summary", "statements"], "additionalProperties": False,
                  "properties": {"verdict": {"type": "string"}, "summary": {"type": "string"}, "statements": {"type": "array", "maxItems": 12,
                  "items": {"type": "object", "required": ["claim", "evidence_ids", "rule_ids"], "additionalProperties": False,
                  "properties": {"claim": {"type": "string"}, "evidence_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                                 "rule_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1}}}}}}
        result = self._llm.generate_structured(system=system, user=user, schema=schema, params=GenerationParams(temperature=0.0, max_output_tokens=2500, seed=0))
        record = validate_explanation(verdict_id=verdict.verdict_id, stored_verdict=verdict.verdict.value,
                                      output=result.output, valid_evidence_ids=evidence_ids, valid_rule_ids=set(verdict.fired_rules))
        return record
