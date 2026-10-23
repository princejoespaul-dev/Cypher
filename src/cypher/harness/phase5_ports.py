"""Ports consumed by Phase 5. Concrete adapters belong to the integrated backend."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID, uuid4

from cypher.harness.phase5_models import (
    Actor,
    AdjudicationDecision,
    BuildRecord,
    CapsuleVersionRecord,
    EvidenceBundle,
    FindingEventRecord,
    FindingPage,
    FindingRecord,
    FixVerificationRecord,
    RegressionSuiteRecord,
    RegressionSuiteRunRecord,
    ReplayRunRecord,
    StoredVerdictRecord,
)


class Phase5Repository(Protocol):
    """Persistence port. Mutating adapter methods must commit their domain write and
    the corresponding hash-chained audit entry in one database transaction where possible.
    """

    def get_run(self, run_id: UUID, project_id: UUID) -> ReplayRunRecord | None: ...
    def get_build(self, build_id: UUID, project_id: UUID) -> BuildRecord | None: ...
    def get_capsule_version(self, capsule_version_id: UUID, project_id: UUID) -> CapsuleVersionRecord | None: ...

    def ensure_open_finding(self, run: ReplayRunRecord, actor_id: UUID) -> FindingRecord: ...
    def get_finding(self, finding_id: UUID, project_id: UUID) -> FindingRecord | None: ...
    def get_finding_by_fingerprint(self, project_id: UUID, fingerprint: str) -> FindingRecord | None: ...
    def list_findings(self, project_id: UUID, cursor: UUID | None, limit: int) -> FindingPage: ...
    def get_current_finding_event(self, finding_id: UUID, project_id: UUID) -> FindingEventRecord | None: ...
    def append_finding_event_if_state(
        self,
        *,
        finding: FindingRecord,
        expected_state: FindingEventRecord | None,
        event_type: str,
        actor_id: UUID,
        run_id: UUID | None = None,
        related_run_ids: tuple[UUID, ...] = (),
        fix_verification_id: UUID | None = None,
        suite_run_id: UUID | None = None,
        build_id: UUID | None = None,
        details: dict[str, object] | None = None,
    ) -> FindingEventRecord | None: ...
    def get_finding_timeline(self, finding_id: UUID, project_id: UUID) -> tuple[FindingEventRecord, ...]: ...

    def save_fix_verification(self, record: FixVerificationRecord, actor: Actor, *, finding: FindingRecord | None) -> None: ...

    def create_regression_suite(self, record: RegressionSuiteRecord, actor: Actor) -> None: ...
    def get_regression_suite(self, suite_id: UUID, project_id: UUID) -> RegressionSuiteRecord | None: ...
    def start_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None: ...
    def finish_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None: ...
    def get_suite_run(self, suite_run_id: UUID, project_id: UUID) -> RegressionSuiteRunRecord | None: ...

    def get_verdict(self, verdict_id: UUID, project_id: UUID) -> StoredVerdictRecord | None: ...
    def get_evidence_bundle(self, run_id: UUID, project_id: UUID) -> EvidenceBundle | None: ...
    def append_verdict(self, record: StoredVerdictRecord, actor: Actor) -> None: ...


class ReplayRunner(Protocol):
    """Runs the existing Phase 4 replay job; it must use only sandbox targets."""

    def replay(self, *, capsule_version_id: UUID, build_id: UUID, project_id: UUID, repeats: int) -> ReplayRunRecord: ...


class PureAdjudicator(Protocol):
    """Adapter to Phase 4's pure, versioned adjudicator implementation."""

    def adjudicate(self, *, evidence: EvidenceBundle, adjudicator_version: str) -> AdjudicationDecision: ...

# Runtime inputs are injected so unit tests and experiment replays can freeze them.


class Clock(Protocol):
    def now(self) -> datetime: ...


class Rng(Protocol):
    def new_uuid(self) -> UUID: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class SystemRng:
    def new_uuid(self) -> UUID:
        return uuid4()
