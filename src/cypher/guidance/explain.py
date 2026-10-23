"""Evidence-cited AI explanation validator; explanations never affect verdicts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from cypher.core.errors import Invalid
from cypher.core.canonical import canonical_json_bytes, sha256_hex


@dataclass(frozen=True, slots=True)
class ExplanationStatement:
    claim: str
    evidence_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExplanationRecord:
    explanation_id: UUID
    verdict_id: UUID
    stored_verdict: str
    summary: str
    statements: tuple[ExplanationStatement, ...]
    generated_by: str = "AI-generated"


def validate_explanation(*, verdict_id: UUID, stored_verdict: str, output: dict[str, Any],
                         valid_evidence_ids: set[str], valid_rule_ids: set[str]) -> ExplanationRecord:
    if output.get("verdict") != stored_verdict:
        raise Invalid("Explanation verdict disagrees with the stored adjudication", code="guidance.explanation_verdict_mismatch")
    summary = output.get("summary")
    rows = output.get("statements")
    if not isinstance(summary, str) or not summary.strip() or not isinstance(rows, list):
        raise Invalid("Explanation must contain a summary and statement list")
    statements: list[ExplanationStatement] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("claim"), str):
            raise Invalid("Each explanation statement must contain a claim")
        evidence_ids = tuple(str(v) for v in row.get("evidence_ids", []))
        rule_ids = tuple(str(v) for v in row.get("rule_ids", []))
        if not evidence_ids or any(eid not in valid_evidence_ids for eid in evidence_ids):
            raise Invalid("Explanation contains an absent or invented evidence id", code="guidance.evidence_citation_invalid")
        if not rule_ids or any(rid not in valid_rule_ids for rid in rule_ids):
            raise Invalid("Explanation contains an absent or invented rule id", code="guidance.rule_citation_invalid")
        statements.append(ExplanationStatement(row["claim"], evidence_ids, rule_ids))
    return ExplanationRecord(uuid4(), verdict_id, stored_verdict, summary, tuple(statements))


def explanation_hash(record: ExplanationRecord) -> str:
    return sha256_hex(canonical_json_bytes({"verdict_id": str(record.verdict_id), "verdict": record.stored_verdict,
        "summary": record.summary, "statements": [{"claim": s.claim, "evidence_ids": s.evidence_ids, "rule_ids": s.rule_ids} for s in record.statements]}))
