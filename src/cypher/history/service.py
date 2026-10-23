"""Reviewed, frozen Cyphrus case library, recommendations and deterministic analytics."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from dataclasses import replace
from threading import RLock
from typing import Any, Callable
from uuid import UUID, uuid4

from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.core.errors import Conflict, Forbidden, Invalid, NotFound
from cypher.history.models import CaseRecord, HistoryRecommendation, OutcomeLabel, RecurrenceReport, ReviewStatus
from cypher.history.retrieval import EmbeddingProvider, hybrid_retrieve


class HistoryService:
    def __init__(self, *, embedding_provider: EmbeddingProvider | None = None,
                 capsule_drafter: Callable[[dict[str, Any]], tuple[dict[str, Any], ...]] | None = None) -> None:
        self._cases: dict[UUID, CaseRecord] = {}
        self._recommendations: dict[UUID, HistoryRecommendation] = {}
        self._embedding = embedding_provider
        self._draft_capsules = capsule_drafter or (lambda _context: ())
        self._lock = RLock()

    def draft_case(self, *, project_id: UUID, finding_id: UUID, vuln_class: str, mutation_dimension: str,
                   method: str, resource_type: str, policy_rule_type: str, pattern_summary: str,
                   fix_pattern: str, evidence_ids: tuple[str, ...], finding_event_ids: tuple[UUID, ...]) -> CaseRecord:
        if not evidence_ids or not finding_event_ids:
            raise Invalid("Case draft needs links to stored evidence and finding events")
        if self._embedding:
            text = f"{vuln_class} {mutation_dimension} {method} {resource_type} {policy_rule_type} {pattern_summary} {fix_pattern}"
            embedding = self._embedding.embed(text)
            model = self._embedding.model_id
        else:
            embedding, model = None, None
        record = CaseRecord(uuid4(), project_id, finding_id, vuln_class, mutation_dimension, method.upper(), resource_type,
                            policy_rule_type, pattern_summary, fix_pattern, OutcomeLabel.ACCEPTED_RISK, ReviewStatus.DRAFT,
                            None, evidence_ids, finding_event_ids, embedding, model, None, datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._cases[record.case_id] = record
        return record

    def review_case(self, *, case_id: UUID, project_id: UUID, label: OutcomeLabel, reviewer_id: UUID,
                    approve: bool = True, supersedes_case_id: UUID | None = None) -> CaseRecord:
        with self._lock:
            if supersedes_case_id is not None:
                old = self._cases.get(supersedes_case_id)
                if old is None or old.project_id != project_id or old.review_status != ReviewStatus.REVIEWED:
                    raise NotFound("Reviewed case to supersede was not found")
                if any(row.project_id == project_id and row.review_status == ReviewStatus.REVIEWED and row.supersedes_case_id == supersedes_case_id
                       for row in self._cases.values()):
                    raise Conflict("This reviewed case already has a reviewed successor")
                if case_id == supersedes_case_id:
                    raise Invalid("A correction must use a new case ID")
            current = self._cases.get(case_id)
            if current is None or current.project_id != project_id:
                raise NotFound("Case not found")
            if current.review_status != ReviewStatus.DRAFT:
                raise Conflict("Reviewed cases are frozen; corrections must create a new case")
            if not approve:
                rejected = replace(current, review_status=ReviewStatus.SUPERSEDED, reviewer_id=reviewer_id)
                self._cases[case_id] = rejected
                return rejected
            reviewed = replace(current, outcome_label=label, review_status=ReviewStatus.REVIEWED, reviewer_id=reviewer_id,
                               supersedes_case_id=supersedes_case_id)
            # Keep the superseded reviewed record unchanged; the new immutable case points to it.
            self._cases[case_id] = reviewed
            return reviewed

    def retrieve(self, *, project_id: UUID, vuln_class: str, mutation_dimension: str, method: str,
                 resource_type: str, query_text: str, limit: int = 5) -> tuple[dict[str, Any], ...]:
        with self._lock:
            reviewed = self._active_reviewed_cases_locked(project_id)
        query_vector = self._embedding.embed(query_text) if self._embedding else None
        rows = hybrid_retrieve(cases=reviewed, project_id=project_id, vuln_class=vuln_class,
                               mutation_dimension=mutation_dimension, method=method, resource_type=resource_type,
                               query_text=query_text, query_embedding=query_vector, limit=limit)
        return tuple({"case_id": str(row.case.case_id), "outcome_label": row.case.outcome_label.value,
                      "pattern_summary": row.case.pattern_summary, "fix_pattern": row.case.fix_pattern,
                      "evidence_ids": list(row.case.evidence_ids), "keyword_rank": row.keyword_rank,
                      "keyword_score": row.keyword_score, "vector_rank": row.vector_rank,
                      "vector_score": row.vector_score, "fused_score": row.fused_score} for row in rows)

    def recommend(self, *, project_id: UUID, query: dict[str, Any], available_evidence_ids: set[str], limit: int = 5) -> HistoryRecommendation:
        retrieved = self.retrieve(project_id=project_id, vuln_class=str(query.get("vuln_class", "")),
                                  mutation_dimension=str(query.get("mutation_dimension", "")), method=str(query.get("method", "GET")),
                                  resource_type=str(query.get("resource_type", "")), query_text=str(query.get("query_text", "")), limit=limit)
        returned_case_ids = {row["case_id"] for row in retrieved}
        drafts = self._draft_capsules({"query": query, "retrieved_cases": retrieved})
        errors: list[str] = []
        cited_case_ids: set[str] = set()
        cited_evidence: set[str] = set()
        for index, draft in enumerate(drafts):
            case_ids = draft.get("case_ids", [])
            evidence_ids = draft.get("evidence_ids", [])
            if not isinstance(case_ids, list) or not case_ids or any(str(case_id) not in returned_case_ids for case_id in case_ids):
                errors.append(f"draft[{index}]: case citations absent or not returned by retrieval")
            if not isinstance(evidence_ids, list) or not evidence_ids or any(str(eid) not in available_evidence_ids for eid in evidence_ids):
                errors.append(f"draft[{index}]: evidence citations absent or unknown")
            cited_case_ids.update(str(v) for v in case_ids if isinstance(v, str))
            cited_evidence.update(str(v) for v in evidence_ids if isinstance(v, str))
        # Invalid recommendations are recorded but never exposed as actionable drafts.
        accepted_drafts = tuple(drafts) if not errors else ()
        query_hash = sha256_hex(canonical_json_bytes(query, permit_float=True))
        with self._lock:
            library_size = len(self._active_reviewed_cases_locked(project_id))
        record = HistoryRecommendation(uuid4(), project_id, "pending_review" if accepted_drafts else "rejected_by_validator",
                                       query_hash, tuple(UUID(value) for value in sorted(cited_case_ids) if value in returned_case_ids),
                                       tuple(sorted(cited_evidence)), accepted_drafts, tuple(errors), library_size)
        with self._lock:
            self._recommendations[record.recommendation_id] = record
        return record

    def recurrence_report(self, *, project_id: UUID, finding_events: tuple[dict[str, Any], ...], findings: tuple[dict[str, Any], ...]) -> RecurrenceReport:
        with self._lock:
            reviewed_cases = self._active_reviewed_cases_locked(project_id)
            library_size = len(reviewed_cases)
            outcomes: dict[str, int] = {}
            for case in reviewed_cases:
                outcomes[case.outcome_label.value] = outcomes.get(case.outcome_label.value, 0) + 1
        by_operation: dict[str, int] = {}
        by_policy: dict[str, int] = {}
        by_fingerprint: dict[str, int] = {}
        for finding in findings:
            if finding.get("project_id") != str(project_id):
                continue
            fingerprint = str(finding.get("fingerprint", ""))
            by_fingerprint[fingerprint] = by_fingerprint.get(fingerprint, 0) + 0
        for event in finding_events:
            if event.get("project_id") != str(project_id):
                continue
            if event.get("event_type") == "reintroduced":
                fp = str(event.get("fingerprint", ""))
                by_fingerprint[fp] = by_fingerprint.get(fp, 0) + 1
                op = str(event.get("operation_id", "unknown"))
                policy = str(event.get("policy_rule_id", "unknown"))
                by_operation[op] = by_operation.get(op, 0) + 1
                by_policy[policy] = by_policy.get(policy, 0) + 1
        return RecurrenceReport(project_id, library_size, tuple(sorted(by_operation.items())), tuple(sorted(by_policy.items())),
                                tuple(sorted((k, v) for k, v in by_fingerprint.items() if v)), tuple(sorted(outcomes.items())))

    def _active_reviewed_cases_locked(self, project_id: UUID) -> tuple[CaseRecord, ...]:
        successors = {row.supersedes_case_id for row in self._cases.values()
                      if row.project_id == project_id and row.review_status == ReviewStatus.REVIEWED and row.supersedes_case_id is not None}
        rows = (row for row in self._cases.values()
                if row.project_id == project_id and row.review_status == ReviewStatus.REVIEWED and row.case_id not in successors)
        return tuple(rows)

    def get_recommendation(self, recommendation_id: UUID, project_id: UUID) -> HistoryRecommendation | None:
        with self._lock:
            row = self._recommendations.get(recommendation_id)
            return row if row and row.project_id == project_id else None
