"""Cyphrus historical case/recommendation contracts."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID


class OutcomeLabel(StrEnum):
    FIX_VERIFIED = "fix_verified"
    FIX_INCOMPLETE = "fix_incomplete"
    RECURRED = "recurred"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class CaseRecord:
    case_id: UUID
    project_id: UUID
    finding_id: UUID
    vuln_class: str
    mutation_dimension: str
    method: str
    resource_type: str
    policy_rule_type: str
    pattern_summary: str
    fix_pattern: str
    outcome_label: OutcomeLabel
    review_status: ReviewStatus
    reviewer_id: UUID | None
    evidence_ids: tuple[str, ...]
    finding_event_ids: tuple[UUID, ...]
    embedding: tuple[float, ...] | None
    embedding_model: str | None
    supersedes_case_id: UUID | None
    created_at: str


@dataclass(frozen=True, slots=True)
class RetrievedCase:
    case: CaseRecord
    keyword_rank: int | None
    keyword_score: float | None
    vector_rank: int | None
    vector_score: float | None
    fused_score: float


@dataclass(frozen=True, slots=True)
class HistoryRecommendation:
    recommendation_id: UUID
    project_id: UUID
    state: str
    query_hash: str
    case_ids: tuple[UUID, ...]
    evidence_ids: tuple[str, ...]
    capsule_drafts: tuple[dict[str, Any], ...]
    validation_errors: tuple[str, ...]
    library_size: int


@dataclass(frozen=True, slots=True)
class RecurrenceReport:
    project_id: UUID
    library_size: int
    recurrence_by_operation: tuple[tuple[str, int], ...]
    recurrence_by_policy_rule: tuple[tuple[str, int], ...]
    reintroduction_count_by_fingerprint: tuple[tuple[str, int], ...]
    reviewed_case_outcomes: tuple[tuple[str, int], ...]
