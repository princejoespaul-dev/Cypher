"""Thread-safe in-memory adapter used by unit tests and local service demos only.

Production deployments must use the PostgreSQL adapter attached to the Phase 0-4
schema and transaction/audit infrastructure; this adapter is intentionally not durable.
"""
from __future__ import annotations

from threading import RLock
from uuid import UUID, uuid4

from cypher.harness.phase5_errors import ConflictError, NotFoundError
from cypher.harness.phase5_models import (
    Actor,
    BuildRecord,
    CapsuleVersionRecord,
    EvidenceBundle,
    FindingEventRecord,
    FindingEventType,
    FindingPage,
    FindingRecord,
    FixVerificationRecord,
    RegressionSuiteRecord,
    RegressionSuiteRunRecord,
    ReplayRunRecord,
    StoredVerdictRecord,
    utc_now,
)


class InMemoryPhase5Repository:
    """Reference adapter with append-only evidence/events and compare-and-append state transitions."""

    def __init__(self) -> None:
        self._lock = RLock()
        self.runs: dict[UUID, ReplayRunRecord] = {}
        self.builds: dict[UUID, BuildRecord] = {}
        self.capsule_versions: dict[UUID, CapsuleVersionRecord] = {}
        self.findings: dict[UUID, FindingRecord] = {}
        self.finding_by_fingerprint: dict[tuple[UUID, str], UUID] = {}
        self.finding_events: dict[UUID, list[FindingEventRecord]] = {}
        self.fix_verifications: dict[UUID, FixVerificationRecord] = {}
        self.suites: dict[UUID, RegressionSuiteRecord] = {}
        self.suite_runs: dict[UUID, RegressionSuiteRunRecord] = {}
        self.verdicts: dict[UUID, StoredVerdictRecord] = {}
        self.evidence: dict[tuple[UUID, UUID], EvidenceBundle] = {}
        self.audit_entries: list[dict[str, object]] = []
        self._event_sequence = 0

    def seed_run(self, run: ReplayRunRecord) -> None:
        with self._lock:
            self.runs[run.run_id] = run
            if run.verdict_id is not None and run.verdict is not None:
                # Test fixtures can seed the verdict details independently via seed_verdict.
                pass

    def seed_build(self, build: BuildRecord) -> None:
        with self._lock:
            self.builds[build.build_id] = build

    def seed_capsule_version(self, version: CapsuleVersionRecord) -> None:
        with self._lock:
            self.capsule_versions[version.capsule_version_id] = version

    def seed_verdict(self, verdict: StoredVerdictRecord) -> None:
        with self._lock:
            self.verdicts[verdict.verdict_id] = verdict
            run = self.runs.get(verdict.run_id)
            if run is not None:
                self.runs[run.run_id] = run.model_copy(update={
                    "verdict_id": verdict.verdict_id,
                    "verdict": verdict.verdict,
                    "signals": verdict.signals,
                })

    def seed_evidence(self, run_id: UUID, project_id: UUID, evidence: EvidenceBundle) -> None:
        with self._lock:
            self.evidence[(run_id, project_id)] = evidence

    def get_run(self, run_id: UUID, project_id: UUID) -> ReplayRunRecord | None:
        with self._lock:
            run = self.runs.get(run_id)
            return run if run is not None and run.project_id == project_id else None

    def get_build(self, build_id: UUID, project_id: UUID) -> BuildRecord | None:
        with self._lock:
            build = self.builds.get(build_id)
            return build if build is not None and build.project_id == project_id else None

    def get_capsule_version(self, capsule_version_id: UUID, project_id: UUID) -> CapsuleVersionRecord | None:
        with self._lock:
            version = self.capsule_versions.get(capsule_version_id)
            return version if version is not None and version.project_id == project_id else None

    def ensure_open_finding(self, run: ReplayRunRecord, actor_id: UUID) -> FindingRecord:
        """Atomic idempotent insert: unique on (project_id, fingerprint)."""
        key = (run.project_id, run.capsule_fingerprint)
        with self._lock:
            existing_id = self.finding_by_fingerprint.get(key)
            if existing_id is not None:
                return self.findings[existing_id]
            finding = FindingRecord(
                finding_id=uuid4(),
                project_id=run.project_id,
                fingerprint=run.capsule_fingerprint,
                capsule_id=run.capsule_id,
                first_seen_build_id=run.build_id,
                created_at=utc_now(),
            )
            self.findings[finding.finding_id] = finding
            self.finding_by_fingerprint[key] = finding.finding_id
            self.finding_events[finding.finding_id] = []
            self._append_event_locked(
                finding=finding,
                event_type=FindingEventType.OPEN.value,
                actor_id=actor_id,
                run_id=run.run_id,
                build_id=run.build_id,
                details={"verdict": run.verdict.value if run.verdict else None},
            )
            return finding

    def get_finding(self, finding_id: UUID, project_id: UUID) -> FindingRecord | None:
        with self._lock:
            item = self.findings.get(finding_id)
            return item if item is not None and item.project_id == project_id else None

    def get_finding_by_fingerprint(self, project_id: UUID, fingerprint: str) -> FindingRecord | None:
        with self._lock:
            finding_id = self.finding_by_fingerprint.get((project_id, fingerprint))
            return self.findings.get(finding_id) if finding_id else None

    def list_findings(self, project_id: UUID, cursor: UUID | None, limit: int) -> FindingPage:
        with self._lock:
            records = [row for row in self.findings.values() if row.project_id == project_id]
            records.sort(key=lambda row: (row.created_at, str(row.finding_id)), reverse=True)
            if cursor is not None:
                anchor_index = next((i for i, row in enumerate(records) if row.finding_id == cursor), None)
                if anchor_index is None:
                    raise ConflictError("pagination.cursor_invalid", "Cursor does not identify a finding in this project")
                records = records[anchor_index + 1:]
            has_more = len(records) > limit
            items = tuple(records[:limit])
            next_cursor = items[-1].finding_id if has_more and items else None
            return FindingPage(items=items, next_cursor=next_cursor)

    def get_current_finding_event(self, finding_id: UUID, project_id: UUID) -> FindingEventRecord | None:
        with self._lock:
            finding = self.findings.get(finding_id)
            if finding is None or finding.project_id != project_id:
                return None
            timeline = self.finding_events.get(finding_id, [])
            return timeline[-1] if timeline else None

    def append_finding_event_if_state(
        self,
        *, finding: FindingRecord,
        expected_state: FindingEventRecord | None,
        event_type: str,
        actor_id: UUID,
        run_id: UUID | None = None,
        related_run_ids: tuple[UUID, ...] = (),
        fix_verification_id: UUID | None = None,
        suite_run_id: UUID | None = None,
        build_id: UUID | None = None,
        details: dict[str, object] | None = None,
    ) -> FindingEventRecord | None:
        with self._lock:
            stored_finding = self.findings.get(finding.finding_id)
            if stored_finding is None or stored_finding.project_id != finding.project_id:
                raise NotFoundError("finding.not_found", "Finding was not found")
            timeline = self.finding_events.setdefault(finding.finding_id, [])
            latest = timeline[-1] if timeline else None
            if (latest.event_id if latest else None) != (expected_state.event_id if expected_state else None):
                return None
            return self._append_event_locked(
                finding=finding,
                event_type=event_type,
                actor_id=actor_id,
                run_id=run_id,
                related_run_ids=related_run_ids,
                fix_verification_id=fix_verification_id,
                suite_run_id=suite_run_id,
                build_id=build_id,
                details=details or {},
            )

    def _append_event_locked(
        self,
        *, finding: FindingRecord,
        event_type: str,
        actor_id: UUID | None,
        run_id: UUID | None = None,
        related_run_ids: tuple[UUID, ...] = (),
        fix_verification_id: UUID | None = None,
        suite_run_id: UUID | None = None,
        build_id: UUID | None = None,
        details: dict[str, object] | None = None,
    ) -> FindingEventRecord:
        self._event_sequence += 1
        event = FindingEventRecord(
            event_id=uuid4(),
            sequence=self._event_sequence,
            project_id=finding.project_id,
            finding_id=finding.finding_id,
            event_type=FindingEventType(event_type),
            actor_id=actor_id,
            run_id=run_id,
            related_run_ids=related_run_ids,
            fix_verification_id=fix_verification_id,
            suite_run_id=suite_run_id,
            build_id=build_id,
            details=details or {},
            created_at=utc_now(),
        )
        self.finding_events.setdefault(finding.finding_id, []).append(event)
        return event

    def get_finding_timeline(self, finding_id: UUID, project_id: UUID) -> tuple[FindingEventRecord, ...]:
        with self._lock:
            finding = self.findings.get(finding_id)
            if finding is None or finding.project_id != project_id:
                return ()
            return tuple(self.finding_events.get(finding_id, []))

    def save_fix_verification(self, record: FixVerificationRecord, actor: Actor, *, finding: FindingRecord | None) -> None:
        with self._lock:
            if record.project_id != actor.project_id or record.created_by != actor.user_id:
                raise ConflictError("fix_verification.actor_scope_mismatch", "Verification actor or project scope did not match")
            if record.verification_id in self.fix_verifications:
                raise ConflictError("fix_verification.duplicate", "Fix verification records are append-only and cannot be overwritten")
            if finding is not None and finding.project_id != actor.project_id:
                raise ConflictError("fix_verification.finding_scope_mismatch", "Finding is outside the actor project")
            if record.outcome.value == "FIX_VERIFIED" and finding is None:
                raise ConflictError("fix_verification.finding_missing", "A verified fix must reference an opened finding")
            self.fix_verifications[record.verification_id] = record
            if record.outcome.value == "FIX_VERIFIED":
                assert finding is not None
                self._append_event_locked(
                    finding=finding,
                    event_type="fixed_verified",
                    actor_id=actor.user_id,
                    related_run_ids=(record.vulnerable_run_id, record.fixed_run_id),
                    fix_verification_id=record.verification_id,
                    build_id=record.fixed_build_id,
                    details={"outcome": record.outcome.value},
                )
            self._audit_locked(actor, "fix_verification.created", str(record.verification_id), {"outcome": record.outcome.value})

    def create_regression_suite(self, record: RegressionSuiteRecord, actor: Actor) -> None:
        with self._lock:
            if record.project_id != actor.project_id:
                raise ConflictError("regression_suite.actor_scope_mismatch", "Suite project did not match actor")
            self.suites[record.suite_id] = record
            self._audit_locked(actor, "regression_suite.created", str(record.suite_id), {"capsule_count": len(record.capsule_version_ids)})

    def get_regression_suite(self, suite_id: UUID, project_id: UUID) -> RegressionSuiteRecord | None:
        with self._lock:
            item = self.suites.get(suite_id)
            return item if item is not None and item.project_id == project_id else None

    def start_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None:
        with self._lock:
            if record.project_id != actor.project_id or record.state.value != "running":
                raise ConflictError("regression_suite_run.invalid_start", "Invalid suite-run start state or project")
            if record.suite_run_id in self.suite_runs:
                raise ConflictError("regression_suite_run.duplicate", "Suite-run ID already exists")
            self.suite_runs[record.suite_run_id] = record
            self._audit_locked(actor, "regression_suite_run.started", str(record.suite_run_id), {"build_id": str(record.build_id)})

    def finish_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None:
        with self._lock:
            current = self.suite_runs.get(record.suite_run_id)
            if current is None or current.project_id != actor.project_id:
                raise NotFoundError("regression_suite_run.not_found", "Suite run was not found")
            if current.state.value != "running" or record.state.value == "running" or record.completed_at is None:
                raise ConflictError("regression_suite_run.invalid_transition", "Only a running suite can transition to a finished state")
            self.suite_runs[record.suite_run_id] = record
            self._audit_locked(actor, "regression_suite_run.finished", str(record.suite_run_id), {
                "failed": record.failed,
                "state": record.state.value,
                "run_count": len(record.run_ids),
            })

    def get_suite_run(self, suite_run_id: UUID, project_id: UUID) -> RegressionSuiteRunRecord | None:
        with self._lock:
            item = self.suite_runs.get(suite_run_id)
            return item if item is not None and item.project_id == project_id else None

    def get_verdict(self, verdict_id: UUID, project_id: UUID) -> StoredVerdictRecord | None:
        with self._lock:
            item = self.verdicts.get(verdict_id)
            return item if item is not None and item.project_id == project_id else None

    def get_evidence_bundle(self, run_id: UUID, project_id: UUID) -> EvidenceBundle | None:
        with self._lock:
            return self.evidence.get((run_id, project_id))

    def append_verdict(self, record: StoredVerdictRecord, actor: Actor) -> None:
        with self._lock:
            if record.project_id != actor.project_id:
                raise ConflictError("verdict.actor_scope_mismatch", "Verdict project did not match actor")
            if record.verdict_id in self.verdicts:
                raise ConflictError("verdict.duplicate", "Verdict IDs are append-only and cannot be reused")
            if record.supersedes_verdict_id is None or record.supersedes_verdict_id not in self.verdicts:
                raise ConflictError("verdict.invalid_supersedes", "Re-adjudication must reference an existing prior verdict")
            prior = self.verdicts[record.supersedes_verdict_id]
            if prior.project_id != actor.project_id or prior.run_id != record.run_id:
                raise ConflictError("verdict.invalid_supersedes", "Prior verdict belongs to a different project or run")
            if any(
                verdict.run_id == record.run_id and verdict.adjudicator_version == record.adjudicator_version
                for verdict in self.verdicts.values()
            ):
                raise ConflictError(
                    "verdict.adjudicator_version_exists",
                    "This run already has a verdict under the requested adjudicator version",
                )
            self.verdicts[record.verdict_id] = record
            run = self.runs.get(record.run_id)
            if run is not None:
                self.runs[run.run_id] = run.model_copy(update={
                    "verdict_id": record.verdict_id,
                    "verdict": record.verdict,
                    "signals": record.signals,
                })
            self._audit_locked(actor, "verdict.readjudicated", str(record.verdict_id), {
                "supersedes_verdict_id": str(record.supersedes_verdict_id),
                "adjudicator_version": record.adjudicator_version,
            })

    def _audit_locked(self, actor: Actor, action: str, object_ref: str, payload: dict[str, object]) -> None:
        # Production adapter must delegate to the app's hash-chained append-only writer.
        self.audit_entries.append({
            "actor_id": str(actor.user_id),
            "project_id": str(actor.project_id),
            "action": action,
            "object_ref": object_ref,
            "payload": payload,
            "created_at": utc_now().isoformat(),
        })
