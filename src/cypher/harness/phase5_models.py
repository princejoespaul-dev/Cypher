"""Strict domain contracts for Cypher backend Phase 5.

This module deliberately contains no I/O so the decision rules remain easy to test.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Role(StrEnum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Verdict(StrEnum):
    VULNERABLE_STATE_CHANGE = "VULNERABLE_STATE_CHANGE"
    VULNERABLE_DATA_EXPOSURE = "VULNERABLE_DATA_EXPOSURE"
    PROTECTED = "PROTECTED"
    INCONCLUSIVE_ENVIRONMENT = "INCONCLUSIVE_ENVIRONMENT"
    INCONCLUSIVE_CONTROL = "INCONCLUSIVE_CONTROL"
    INCONCLUSIVE_AMBIGUOUS = "INCONCLUSIVE_AMBIGUOUS"
    INCONCLUSIVE_FLAKY = "INCONCLUSIVE_FLAKY"

    @property
    def is_vulnerable(self) -> bool:
        return self.value.startswith("VULNERABLE_")

    @property
    def is_inconclusive(self) -> bool:
        return self.value.startswith("INCONCLUSIVE_")


class BuildLabel(StrEnum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    PARTIAL_FIX = "partial_fix"
    OVER_BLOCKING = "over_blocking"
    REINTRODUCED = "reintroduced"
    OTHER = "other"


class FixOutcome(StrEnum):
    FIX_VERIFIED = "FIX_VERIFIED"
    FIX_INCOMPLETE = "FIX_INCOMPLETE"
    FIX_BREAKS_CONTROL = "FIX_BREAKS_CONTROL"
    FIX_UNVERIFIABLE = "FIX_UNVERIFIABLE"


class FindingEventType(StrEnum):
    OPEN = "open"
    FIXED_VERIFIED = "fixed_verified"
    REINTRODUCED = "reintroduced"


class RunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_finished(self) -> bool:
        return self in {self.SUCCEEDED, self.COMPLETED, self.FAILED, self.CANCELLED}


class SuiteState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Actor(StrictModel):
    user_id: UUID
    project_id: UUID
    role: Role


class BuildRecord(StrictModel):
    build_id: UUID
    project_id: UUID
    target_id: UUID
    label: BuildLabel
    sandbox_only: bool


class CapsuleVersionRecord(StrictModel):
    capsule_version_id: UUID
    project_id: UUID
    capsule_id: UUID
    target_id: UUID
    version: int = Field(ge=1)
    status: str
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ReplayRunRecord(StrictModel):
    run_id: UUID
    project_id: UUID
    target_id: UUID
    capsule_id: UUID
    capsule_version_id: UUID
    capsule_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    build_id: UUID
    build_label: BuildLabel
    run_state: RunState
    sandbox_only: bool
    verdict_id: UUID | None = None
    verdict: Verdict | None = None
    signals: dict[str, bool | None] = Field(default_factory=dict)


class FindingRecord(StrictModel):
    finding_id: UUID
    project_id: UUID
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    capsule_id: UUID
    first_seen_build_id: UUID
    created_at: datetime


class FindingPage(StrictModel):
    items: tuple[FindingRecord, ...]
    next_cursor: UUID | None = None


class FindingEventRecord(StrictModel):
    event_id: UUID
    sequence: int = Field(ge=1)
    project_id: UUID
    finding_id: UUID
    event_type: FindingEventType
    actor_id: UUID | None = None
    run_id: UUID | None = None
    related_run_ids: tuple[UUID, ...] = ()
    fix_verification_id: UUID | None = None
    suite_run_id: UUID | None = None
    build_id: UUID | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime


class FixVerificationRecord(StrictModel):
    verification_id: UUID
    project_id: UUID
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    capsule_version_id: UUID
    vulnerable_build_id: UUID
    fixed_build_id: UUID
    vulnerable_run_id: UUID
    fixed_run_id: UUID
    outcome: FixOutcome
    created_by: UUID
    created_at: datetime


class RegressionSuiteRecord(StrictModel):
    suite_id: UUID
    project_id: UUID
    name: str = Field(min_length=1, max_length=160)
    capsule_version_ids: tuple[UUID, ...] = Field(min_length=1, max_length=100)
    created_by: UUID
    created_at: datetime

    @field_validator("capsule_version_ids")
    @classmethod
    def no_duplicate_capsules(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("capsule_version_ids must not contain duplicates")
        return value


class RegressionSuiteRunRecord(StrictModel):
    suite_run_id: UUID
    project_id: UUID
    suite_id: UUID
    build_id: UUID
    state: SuiteState
    failed: bool
    run_ids: tuple[UUID, ...] = ()
    error_code: str | None = None
    error_message: str | None = None
    created_by: UUID
    started_at: datetime
    completed_at: datetime | None = None


class StoredVerdictRecord(StrictModel):
    verdict_id: UUID
    project_id: UUID
    run_id: UUID
    verdict: Verdict
    fired_rules: tuple[str, ...]
    signals: dict[str, bool | None]
    completeness_score: float = Field(ge=0.0, le=1.0)
    adjudicator_version: str = Field(min_length=1, max_length=64)
    supersedes_verdict_id: UUID | None = None
    created_at: datetime


class EvidenceBundle(StrictModel):
    """Previously captured, redacted input needed for pure re-adjudication."""

    capsule: dict[str, JsonValue]
    observations: tuple[dict[str, JsonValue], ...]
    state_snapshots: tuple[dict[str, JsonValue], ...]
    config: dict[str, JsonValue]


class AdjudicationDecision(StrictModel):
    verdict: Verdict
    fired_rules: tuple[str, ...]
    signals: dict[str, bool | None]
    completeness_score: float = Field(ge=0.0, le=1.0)
    adjudicator_version: str = Field(min_length=1, max_length=64)


class FixVerificationRequest(StrictModel):
    vulnerable_run_id: UUID
    fixed_run_id: UUID


class RegressionSuiteCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    capsule_version_ids: tuple[UUID, ...] = Field(min_length=1, max_length=100)

    @field_validator("capsule_version_ids")
    @classmethod
    def no_duplicate_capsules(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("capsule_version_ids must not contain duplicates")
        return value


class RegressionSuiteRunRequest(StrictModel):
    build_id: UUID
    repeats: int = Field(default=3, ge=1, le=10)


class ReadjudicateRequest(StrictModel):
    adjudicator_version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def utc_now() -> datetime:
    """Utility for adapters/tests; never used by the adjudicator."""
    return datetime.now(timezone.utc)
