"""SQLAlchemy/PostgreSQL persistence adapter for Phase 5.

The adapter uses the table/column names specified in Backend Plan.md. Because the
Phase 0-4 repository itself was not provided, it intentionally accepts the existing
content-addressed evidence reader and uses a narrowly specified audit writer port.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Protocol, cast
from pydantic import JsonValue, TypeAdapter
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from cypher.harness.phase5_errors import ConflictError, NotFoundError
from cypher.harness.phase5_ports import Clock, Rng, SystemClock, SystemRng
from cypher.harness.phase5_models import (
    Actor,
    BuildLabel,
    BuildRecord,
    CapsuleVersionRecord,
    EvidenceBundle,
    FindingEventRecord,
    FindingEventType,
    FindingPage,
    FindingRecord,
    FixOutcome,
    FixVerificationRecord,
    RegressionSuiteRecord,
    RegressionSuiteRunRecord,
    ReplayRunRecord,
    RunState,
    StoredVerdictRecord,
    SuiteState,
    Verdict,
)


class EvidenceBlobReader(Protocol):
    """Read already-redacted, content-addressed evidence by SHA-256 key."""

    def read_json_or_text(self, *, content_sha256: str, project_id: UUID) -> JsonValue | None: ...


class AuditAppender(Protocol):
    def append(
        self,
        *,
        session: Session,
        actor_id: UUID,
        project_id: UUID,
        action: str,
        object_ref: str,
        payload: Mapping[str, object],
    ) -> None: ...


class HashChainedAuditAppender:
    """Reference implementation for the audit_log columns in the plan.

    The app's project context/RLS must already be set on the SQLAlchemy transaction.
    A transaction-level advisory lock serializes chain extension across API workers.
    """

    def append(
        self,
        *,
        session: Session,
        actor_id: UUID,
        project_id: UUID,
        action: str,
        object_ref: str,
        payload: Mapping[str, object],
    ) -> None:
        # RLS makes the integrity chain project-local. A transaction lock serializes
        # each project's appenders, and reads remain visible under the same RLS scope.
        session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:project_id))"), {"project_id": str(project_id)})
        prior = session.execute(
            text("SELECT hash FROM audit_log WHERE project_id = :project_id ORDER BY seq DESC LIMIT 1 FOR UPDATE"),
            {"project_id": project_id},
        ).mappings().first()
        prev_hash = str(prior["hash"]) if prior is not None else "0" * 64
        payload_sha256 = hashlib.sha256(_canonical_json(dict(payload))).hexdigest()
        content = {
            "actor_id": str(actor_id),
            "action": action,
            "object_ref": object_ref,
            "payload_sha256": payload_sha256,
            "project_id": str(project_id),
        }
        digest = hashlib.sha256(prev_hash.encode("ascii") + _canonical_json(content)).hexdigest()
        session.execute(
            text(
                """INSERT INTO audit_log (project_id, actor_id, action, object_ref, payload_sha256, prev_hash, hash)
                   VALUES (:project_id, :actor_id, :action, :object_ref, :payload_sha256, :prev_hash, :hash)"""
            ),
            {
                "project_id": project_id,
                "actor_id": actor_id,
                "action": action,
                "object_ref": object_ref,
                "payload_sha256": payload_sha256,
                "prev_hash": prev_hash,
                "hash": digest,
            },
        )


def _canonical_json(value: object) -> bytes:
    # The objects hashed here contain only strings, bools, nulls, arrays and simple
    # numbers. Capsule AIC hashing itself must continue to use the Phase 2 RFC 8785 helper.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _capsule_fingerprint(content: Mapping[str, object]) -> str:
    target = content.get("target", {})
    policy = content.get("policy", {})
    mutation = content.get("counterfactual", {})
    resource = content.get("resource", {})
    mutation_data = mutation.get("mutation", {}) if isinstance(mutation, Mapping) else {}
    fingerprint_source = {
        "operation_template": {
            "operation_id": target.get("operation_id") if isinstance(target, Mapping) else None,
            "method": target.get("method") if isinstance(target, Mapping) else None,
            "path": target.get("path") if isinstance(target, Mapping) else None,
        },
        "mutation_dimension": mutation_data.get("dimension") if isinstance(mutation_data, Mapping) else None,
        "policy_rule_id": policy.get("rule_id") if isinstance(policy, Mapping) else None,
        "resource_type": resource.get("type") if isinstance(resource, Mapping) else None,
    }
    if any(value is None for value in [
        fingerprint_source["operation_template"]["operation_id"],
        fingerprint_source["mutation_dimension"],
        fingerprint_source["policy_rule_id"],
        fingerprint_source["resource_type"],
    ]):
        raise ValueError("AIC is missing fields required to calculate its recurrence fingerprint")
    return hashlib.sha256(_canonical_json(fingerprint_source)).hexdigest()


class SqlAlchemyPhase5Repository:
    """PostgreSQL adapter implementing the Phase5Repository port.

    ``session_factory`` must produce a SQLAlchemy Session. The integrated app must
    set transaction-local ``app.project_id`` before any query so PostgreSQL RLS applies.
    ``config_loader`` supplies the frozen adjudicator configuration for a replay.
    """

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        audit_appender: AuditAppender,
        evidence_reader: EvidenceBlobReader,
        config_loader: Callable[[UUID, UUID], Mapping[str, JsonValue]] | None = None,
        clock: Clock | None = None,
        rng: Rng | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit = audit_appender
        self._evidence_reader = evidence_reader
        self._config_loader = config_loader or (lambda _run_id, _project_id: {})
        self._clock = clock or SystemClock()
        self._rng = rng or SystemRng()

    def _session(self) -> Session:
        return self._session_factory()

    @staticmethod
    def _set_project(session: Session, project_id: UUID) -> None:
        session.execute(text("SELECT set_config('app.project_id', :project_id, true)"), {"project_id": str(project_id)})

    def get_run(self, run_id: UUID, project_id: UUID) -> ReplayRunRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text(
                    """SELECT rr.id AS run_id, c.project_id, t.id AS target_id, c.id AS capsule_id,
                              cv.id AS capsule_version_id, cv.content, tb.id AS build_id, tb.label AS build_label,
                              rr.state AS run_state, t.sandbox_only,
                              v.id AS verdict_id, v.verdict, v.signals
                       FROM replay_runs rr
                       JOIN capsule_versions cv ON cv.id = rr.capsule_version_id
                       JOIN capsules c ON c.id = cv.capsule_id
                       JOIN target_builds tb ON tb.id = rr.build_id
                       JOIN targets t ON t.id = tb.target_id
                       LEFT JOIN LATERAL (
                           SELECT vv.id, vv.verdict, vv.signals
                           FROM verdicts vv
                           WHERE vv.run_id = rr.id
                           ORDER BY vv.verdict_seq DESC
                           LIMIT 1
                       ) v ON TRUE
                       WHERE rr.id = :run_id AND c.project_id = :project_id"""
                ),
                {"run_id": run_id, "project_id": project_id},
            ).mappings().first()
            if row is None:
                return None
            content = _mapping(row["content"])
            fingerprint = _capsule_fingerprint(content)
            return ReplayRunRecord(
                run_id=row["run_id"],
                project_id=row["project_id"],
                target_id=row["target_id"],
                capsule_id=row["capsule_id"],
                capsule_version_id=row["capsule_version_id"],
                capsule_fingerprint=fingerprint,
                build_id=row["build_id"],
                build_label=BuildLabel(str(row["build_label"])),
                run_state=RunState(str(row["run_state"])),
                sandbox_only=bool(row["sandbox_only"]),
                verdict_id=row["verdict_id"],
                verdict=Verdict(str(row["verdict"])) if row["verdict"] is not None else None,
                signals=_signals(row["signals"]) if row["signals"] is not None else {},
            )

    def get_build(self, build_id: UUID, project_id: UUID) -> BuildRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text(
                    """SELECT tb.id AS build_id, t.project_id, t.id AS target_id,
                              tb.label, t.sandbox_only
                       FROM target_builds tb JOIN targets t ON t.id = tb.target_id
                       WHERE tb.id = :build_id AND t.project_id = :project_id"""
                ),
                {"build_id": build_id, "project_id": project_id},
            ).mappings().first()
            if row is None:
                return None
            return BuildRecord(
                build_id=row["build_id"], project_id=row["project_id"], target_id=row["target_id"],
                label=BuildLabel(str(row["label"])), sandbox_only=bool(row["sandbox_only"]),
            )

    def get_capsule_version(self, capsule_version_id: UUID, project_id: UUID) -> CapsuleVersionRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text(
                    """SELECT cv.id AS capsule_version_id, c.project_id, c.id AS capsule_id,
                              pv.target_id, cv.version, cv.content,
                              (SELECT cse.status FROM capsule_status_events cse
                               WHERE cse.capsule_version_id = cv.id ORDER BY cse.at DESC LIMIT 1) AS status
                       FROM capsule_versions cv
                       JOIN capsules c ON c.id = cv.capsule_id
                       LEFT JOIN policy_versions pv ON pv.id::text = cv.content #>> '{policy,policy_version_id}'
                       WHERE cv.id = :version_id AND c.project_id = :project_id"""
                ),
                {"version_id": capsule_version_id, "project_id": project_id},
            ).mappings().first()
            if row is None or row["target_id"] is None:
                return None
            content = _mapping(row["content"])
            return CapsuleVersionRecord(
                capsule_version_id=row["capsule_version_id"], project_id=row["project_id"],
                capsule_id=row["capsule_id"], target_id=row["target_id"], version=int(row["version"]),
                status=str(row["status"] or "draft"), fingerprint=_capsule_fingerprint(content),
            )

    def ensure_open_finding(self, run: ReplayRunRecord, actor_id: UUID) -> FindingRecord:
        with self._session() as session, session.begin():
            self._set_project(session, run.project_id)
            candidate_id = self._rng.new_uuid()
            inserted = session.execute(
                text(
                    """INSERT INTO findings (id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at)
                       VALUES (:finding_id, :project_id, :fingerprint, :capsule_id, :build_id, :created_at)
                       ON CONFLICT (project_id, fingerprint) DO NOTHING
                       RETURNING id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at"""
                ),
                {
                    "finding_id": candidate_id, "project_id": run.project_id, "fingerprint": run.capsule_fingerprint,
                    "capsule_id": run.capsule_id, "build_id": run.build_id, "created_at": self._clock.now(),
                },
            ).mappings().first()
            created = inserted is not None
            if inserted is None:
                inserted = session.execute(
                    text("""SELECT id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at
                            FROM findings WHERE project_id = :project_id AND fingerprint = :fingerprint FOR UPDATE"""),
                    {"project_id": run.project_id, "fingerprint": run.capsule_fingerprint},
                ).mappings().one()
            finding = _finding_from_row(inserted)
            if created:
                self._insert_finding_event(
                    session, finding=finding, event_type=FindingEventType.OPEN.value, actor_id=actor_id,
                    run_id=run.run_id, build_id=run.build_id,
                    details={"verdict": run.verdict.value if run.verdict else None},
                )
                self._audit.append(
                    session=session, actor_id=actor_id, project_id=run.project_id,
                    action="finding.opened", object_ref=str(finding.finding_id),
                    payload={"fingerprint": finding.fingerprint, "run_id": str(run.run_id)},
                )
            return finding

    def get_finding(self, finding_id: UUID, project_id: UUID) -> FindingRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("""SELECT id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at
                        FROM findings WHERE id = :finding_id AND project_id = :project_id"""),
                {"finding_id": finding_id, "project_id": project_id},
            ).mappings().first()
            return _finding_from_row(row) if row is not None else None

    def get_finding_by_fingerprint(self, project_id: UUID, fingerprint: str) -> FindingRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("""SELECT id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at
                        FROM findings WHERE project_id = :project_id AND fingerprint = :fingerprint"""),
                {"project_id": project_id, "fingerprint": fingerprint},
            ).mappings().first()
            return _finding_from_row(row) if row is not None else None

    def list_findings(self, project_id: UUID, cursor: UUID | None, limit: int) -> FindingPage:
        with self._session() as session:
            self._set_project(session, project_id)
            if cursor is not None:
                anchor = session.execute(
                    text("SELECT created_at FROM findings WHERE id=:cursor AND project_id=:project_id"),
                    {"cursor": cursor, "project_id": project_id},
                ).scalar_one_or_none()
                if anchor is None:
                    raise ConflictError("pagination.cursor_invalid", "Cursor does not identify a finding in this project")
                rows = session.execute(
                    text("""SELECT id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at
                            FROM findings WHERE project_id=:project_id
                              AND (created_at, id) < (
                                  SELECT created_at, id FROM findings WHERE id=:cursor AND project_id=:project_id
                              )
                            ORDER BY created_at DESC, id DESC LIMIT :limit_plus_one"""),
                    {"project_id": project_id, "cursor": cursor, "limit_plus_one": limit + 1},
                ).mappings().all()
            else:
                rows = session.execute(
                    text("""SELECT id AS finding_id, project_id, fingerprint, capsule_id, first_seen_build_id, created_at
                            FROM findings WHERE project_id=:project_id
                            ORDER BY created_at DESC, id DESC LIMIT :limit_plus_one"""),
                    {"project_id": project_id, "limit_plus_one": limit + 1},
                ).mappings().all()
            has_more = len(rows) > limit
            items = tuple(_finding_from_row(row) for row in rows[:limit])
            next_cursor = items[-1].finding_id if has_more and items else None
            return FindingPage(items=items, next_cursor=next_cursor)

    def get_current_finding_event(self, finding_id: UUID, project_id: UUID) -> FindingEventRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("""SELECT id AS event_id, finding_events.* FROM finding_events WHERE finding_id = :finding_id AND project_id = :project_id
                        ORDER BY event_seq DESC LIMIT 1"""),
                {"finding_id": finding_id, "project_id": project_id},
            ).mappings().first()
            return _event_from_row(row) if row is not None else None

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
        with self._session() as session, session.begin():
            self._set_project(session, finding.project_id)
            found = session.execute(
                text("SELECT id FROM findings WHERE id = :finding_id AND project_id = :project_id FOR UPDATE"),
                {"finding_id": finding.finding_id, "project_id": finding.project_id},
            ).first()
            if found is None:
                raise NotFoundError("finding.not_found", "Finding was not found")
            latest_row = session.execute(
                text("""SELECT id AS event_id, finding_events.* FROM finding_events WHERE finding_id = :finding_id
                        ORDER BY event_seq DESC LIMIT 1"""),
                {"finding_id": finding.finding_id},
            ).mappings().first()
            latest = _event_from_row(latest_row) if latest_row is not None else None
            if (latest.event_id if latest else None) != (expected_state.event_id if expected_state else None):
                return None
            event = self._insert_finding_event(
                session, finding=finding, event_type=event_type, actor_id=actor_id, run_id=run_id,
                related_run_ids=related_run_ids, fix_verification_id=fix_verification_id,
                suite_run_id=suite_run_id, build_id=build_id, details=details or {},
            )
            self._audit.append(
                session=session, actor_id=actor_id, project_id=finding.project_id,
                action=f"finding.{event_type}", object_ref=str(finding.finding_id),
                payload={"event_id": str(event.event_id), "run_id": str(run_id) if run_id else None},
            )
            return event

    def get_finding_timeline(self, finding_id: UUID, project_id: UUID) -> tuple[FindingEventRecord, ...]:
        with self._session() as session:
            self._set_project(session, project_id)
            rows = session.execute(
                text("""SELECT id AS event_id, finding_events.* FROM finding_events WHERE finding_id = :finding_id AND project_id = :project_id
                        ORDER BY event_seq ASC"""),
                {"finding_id": finding_id, "project_id": project_id},
            ).mappings().all()
            return tuple(_event_from_row(row) for row in rows)

    def save_fix_verification(self, record: FixVerificationRecord, actor: Actor, *, finding: FindingRecord | None) -> None:
        with self._session() as session, session.begin():
            self._set_project(session, actor.project_id)
            if record.project_id != actor.project_id or record.created_by != actor.user_id:
                raise ConflictError("fix_verification.actor_scope_mismatch", "Verification actor or project scope did not match")
            if record.outcome == FixOutcome.FIX_VERIFIED and (finding is None or finding.project_id != actor.project_id):
                raise ConflictError("fix_verification.finding_missing", "A verified fix must reference a finding in this project")
            session.execute(
                text("""INSERT INTO fix_verifications
                        (id, project_id, fingerprint, capsule_version_id, vulnerable_build_id, fixed_build_id,
                         vulnerable_run_id, fixed_run_id, outcome, created_by, created_at)
                        VALUES (:id, :project_id, :fingerprint, :capsule_version_id, :vulnerable_build_id, :fixed_build_id,
                                :vulnerable_run_id, :fixed_run_id, :outcome, :created_by, :created_at)"""),
                {
                    "id": record.verification_id, "project_id": record.project_id, "fingerprint": record.fingerprint,
                    "capsule_version_id": record.capsule_version_id, "vulnerable_build_id": record.vulnerable_build_id,
                    "fixed_build_id": record.fixed_build_id, "vulnerable_run_id": record.vulnerable_run_id,
                    "fixed_run_id": record.fixed_run_id, "outcome": record.outcome.value,
                    "created_by": record.created_by, "created_at": record.created_at,
                },
            )
            if record.outcome == FixOutcome.FIX_VERIFIED and finding is not None:
                session.execute(
                    text("SELECT id FROM findings WHERE id = :finding_id AND project_id = :project_id FOR UPDATE"),
                    {"finding_id": finding.finding_id, "project_id": actor.project_id},
                ).one()
                self._insert_finding_event(
                    session, finding=finding, event_type=FindingEventType.FIXED_VERIFIED.value,
                    actor_id=actor.user_id, related_run_ids=(record.vulnerable_run_id, record.fixed_run_id),
                    fix_verification_id=record.verification_id, details={"outcome": record.outcome.value},
                )
            self._audit.append(
                session=session, actor_id=actor.user_id, project_id=actor.project_id,
                action="fix_verification.created", object_ref=str(record.verification_id),
                payload={"outcome": record.outcome.value, "fingerprint": record.fingerprint},
            )

    def create_regression_suite(self, record: RegressionSuiteRecord, actor: Actor) -> None:
        with self._session() as session, session.begin():
            self._set_project(session, actor.project_id)
            if record.project_id != actor.project_id:
                raise ConflictError("regression_suite.actor_scope_mismatch", "Suite project did not match actor")
            session.execute(
                text("""INSERT INTO regression_suites (id, project_id, name, created_by, created_at)
                        VALUES (:id, :project_id, :name, :created_by, :created_at)"""),
                {"id": record.suite_id, "project_id": record.project_id, "name": record.name,
                 "created_by": record.created_by, "created_at": record.created_at},
            )
            for ordinal, capsule_version_id in enumerate(record.capsule_version_ids):
                session.execute(
                    text("""INSERT INTO regression_suite_capsules (project_id, suite_id, capsule_version_id, ordinal)
                            VALUES (:project_id, :suite_id, :capsule_version_id, :ordinal)"""),
                    {"project_id": record.project_id, "suite_id": record.suite_id,
                     "capsule_version_id": capsule_version_id, "ordinal": ordinal},
                )
            self._audit.append(session=session, actor_id=actor.user_id, project_id=actor.project_id,
                               action="regression_suite.created", object_ref=str(record.suite_id),
                               payload={"capsule_count": len(record.capsule_version_ids)})

    def get_regression_suite(self, suite_id: UUID, project_id: UUID) -> RegressionSuiteRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("SELECT id, project_id, name, created_by, created_at FROM regression_suites WHERE id=:id AND project_id=:project_id"),
                {"id": suite_id, "project_id": project_id},
            ).mappings().first()
            if row is None:
                return None
            capsules = session.execute(
                text("""SELECT capsule_version_id FROM regression_suite_capsules
                        WHERE suite_id = :suite_id AND project_id = :project_id ORDER BY ordinal"""),
                {"suite_id": suite_id, "project_id": project_id},
            ).scalars().all()
            return RegressionSuiteRecord(
                suite_id=row["id"], project_id=row["project_id"], name=row["name"],
                capsule_version_ids=tuple(capsules), created_by=row["created_by"], created_at=row["created_at"],
            )

    def start_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None:
        with self._session() as session, session.begin():
            self._set_project(session, actor.project_id)
            if record.project_id != actor.project_id or record.state != SuiteState.RUNNING:
                raise ConflictError("regression_suite_run.invalid_start", "Invalid suite-run start state or project")
            session.execute(
                text("""INSERT INTO regression_suite_runs
                        (id, project_id, suite_id, build_id, state, failed, run_ids, created_by, started_at)
                        VALUES (:id, :project_id, :suite_id, :build_id, :state, false, :run_ids, :created_by, :started_at)"""),
                {"id": record.suite_run_id, "project_id": record.project_id, "suite_id": record.suite_id,
                 "build_id": record.build_id, "state": record.state.value, "run_ids": [],
                 "created_by": record.created_by, "started_at": record.started_at},
            )
            self._audit.append(session=session, actor_id=actor.user_id, project_id=actor.project_id,
                               action="regression_suite_run.started", object_ref=str(record.suite_run_id),
                               payload={"build_id": str(record.build_id)})

    def finish_suite_run(self, record: RegressionSuiteRunRecord, actor: Actor) -> None:
        with self._session() as session, session.begin():
            self._set_project(session, actor.project_id)
            updated = session.execute(
                text("""UPDATE regression_suite_runs
                        SET state=:state, failed=:failed, run_ids=:run_ids,
                            completed_at=:completed_at, error_code=:error_code, error_message=:error_message
                        WHERE id=:id AND project_id=:project_id AND state='running'"""),
                {"state": record.state.value, "failed": record.failed, "run_ids": list(record.run_ids),
                 "completed_at": record.completed_at, "error_code": record.error_code,
                 "error_message": record.error_message, "id": record.suite_run_id, "project_id": actor.project_id},
            )
            if updated.rowcount != 1:
                raise ConflictError("regression_suite_run.invalid_transition", "Only a running suite can transition to a finished state")
            self._audit.append(session=session, actor_id=actor.user_id, project_id=actor.project_id,
                               action="regression_suite_run.finished", object_ref=str(record.suite_run_id),
                               payload={"state": record.state.value, "failed": record.failed, "run_count": len(record.run_ids)})

    def get_suite_run(self, suite_run_id: UUID, project_id: UUID) -> RegressionSuiteRunRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("SELECT * FROM regression_suite_runs WHERE id=:id AND project_id=:project_id"),
                {"id": suite_run_id, "project_id": project_id},
            ).mappings().first()
            return _suite_run_from_row(row) if row is not None else None

    def get_verdict(self, verdict_id: UUID, project_id: UUID) -> StoredVerdictRecord | None:
        with self._session() as session:
            self._set_project(session, project_id)
            row = session.execute(
                text("""SELECT v.id, c.project_id, v.run_id, v.verdict, v.fired_rules, v.signals,
                              v.completeness_score, v.adjudicator_version, v.supersedes_verdict_id, v.created_at
                       FROM verdicts v JOIN replay_runs rr ON rr.id=v.run_id
                       JOIN capsule_versions cv ON cv.id=rr.capsule_version_id
                       JOIN capsules c ON c.id=cv.capsule_id
                       WHERE v.id=:verdict_id AND c.project_id=:project_id"""),
                {"verdict_id": verdict_id, "project_id": project_id},
            ).mappings().first()
            return _verdict_from_row(row) if row is not None else None

    def get_evidence_bundle(self, run_id: UUID, project_id: UUID) -> EvidenceBundle | None:
        with self._session() as session:
            self._set_project(session, project_id)
            capsule_row = session.execute(
                text("""SELECT cv.content FROM replay_runs rr
                        JOIN capsule_versions cv ON cv.id=rr.capsule_version_id
                        JOIN capsules c ON c.id=cv.capsule_id
                        WHERE rr.id=:run_id AND c.project_id=:project_id"""),
                {"run_id": run_id, "project_id": project_id},
            ).mappings().first()
            if capsule_row is None:
                return None
            observation_rows = session.execute(
                text("""SELECT step, redacted_request, status, redacted_headers, body_sha256,
                              extracted_fields, latency_ms
                       FROM observations WHERE run_id=:run_id ORDER BY step ASC"""),
                {"run_id": run_id},
            ).mappings().all()
            state_rows = session.execute(
                text("""SELECT phase, probe_name, result_sha256 FROM state_snapshots
                        WHERE run_id=:run_id ORDER BY phase, probe_name"""),
                {"run_id": run_id},
            ).mappings().all()
            observations: list[dict[str, object]] = []
            for row in observation_rows:
                item: dict[str, object] = {
                    "step": row["step"],
                    "request": _json_value(row["redacted_request"]),
                    "status": row["status"],
                    "headers": _json_value(row["redacted_headers"]),
                    "body_sha256": row["body_sha256"],
                    "extracted_fields": _json_value(row["extracted_fields"]),
                    "latency_ms": row["latency_ms"],
                }
                if row["body_sha256"]:
                    body = self._evidence_reader.read_json_or_text(content_sha256=str(row["body_sha256"]), project_id=project_id)
                    if body is None:
                        return None
                    item["response_body"] = body
                observations.append(item)
            state_snapshots: list[dict[str, object]] = []
            for row in state_rows:
                value = self._evidence_reader.read_json_or_text(content_sha256=str(row["result_sha256"]), project_id=project_id)
                if value is None:
                    return None
                state_snapshots.append({"phase": row["phase"], "probe_name": row["probe_name"], "result": value})
            config = self._config_loader(run_id, project_id)
            return EvidenceBundle.model_validate({
                "capsule": _mapping(capsule_row["content"]),
                "observations": observations,
                "state_snapshots": state_snapshots,
                "config": dict(config),
            })

    def append_verdict(self, record: StoredVerdictRecord, actor: Actor) -> None:
        with self._session() as session, session.begin():
            self._set_project(session, actor.project_id)
            if record.project_id != actor.project_id or record.supersedes_verdict_id is None:
                raise ConflictError("verdict.invalid_supersedes", "Re-adjudication must supersede an existing verdict in this project")
            prior = session.execute(
                text("""SELECT v.id, v.run_id FROM verdicts v
                        JOIN replay_runs rr ON rr.id=v.run_id
                        JOIN capsule_versions cv ON cv.id=rr.capsule_version_id
                        JOIN capsules c ON c.id=cv.capsule_id
                        WHERE v.id=:prior_id AND c.project_id=:project_id FOR UPDATE"""),
                {"prior_id": record.supersedes_verdict_id, "project_id": actor.project_id},
            ).mappings().first()
            if prior is None or prior["run_id"] != record.run_id:
                raise ConflictError("verdict.invalid_supersedes", "Prior verdict belongs to a different project or run")
            version_exists = session.execute(
                text("SELECT 1 FROM verdicts WHERE run_id = :run_id AND adjudicator_version = :version LIMIT 1"),
                {"run_id": record.run_id, "version": record.adjudicator_version},
            ).first()
            if version_exists is not None:
                raise ConflictError(
                    "verdict.adjudicator_version_exists",
                    "This run already has a verdict under the requested adjudicator version",
                )
            session.execute(
                text("""INSERT INTO verdicts
                        (id, project_id, run_id, verdict, fired_rules, signals, completeness_score,
                         adjudicator_version, supersedes_verdict_id, created_at)
                        VALUES (:id, :project_id, :run_id, :verdict, :fired_rules, CAST(:signals AS jsonb), :completeness_score,
                                :adjudicator_version, :supersedes_verdict_id, :created_at)"""),
                {"id": record.verdict_id, "project_id": record.project_id, "run_id": record.run_id, "verdict": record.verdict.value,
                 "fired_rules": list(record.fired_rules), "signals": json.dumps(record.signals, sort_keys=True, separators=(",", ":")),
                 "completeness_score": record.completeness_score, "adjudicator_version": record.adjudicator_version,
                 "supersedes_verdict_id": record.supersedes_verdict_id, "created_at": record.created_at},
            )
            self._audit.append(session=session, actor_id=actor.user_id, project_id=actor.project_id,
                               action="verdict.readjudicated", object_ref=str(record.verdict_id),
                               payload={"supersedes_verdict_id": str(record.supersedes_verdict_id),
                                        "adjudicator_version": record.adjudicator_version})

    @staticmethod
    def _insert_finding_event(
        session: Session,
        *,
        finding: FindingRecord,
        event_type: str,
        actor_id: UUID,
        run_id: UUID | None = None,
        related_run_ids: tuple[UUID, ...] = (),
        fix_verification_id: UUID | None = None,
        suite_run_id: UUID | None = None,
        build_id: UUID | None = None,
        details: dict[str, object] | None = None,
    ) -> FindingEventRecord:
        event_id = self._rng.new_uuid()
        created_at = self._clock.now()
        row = session.execute(
            text("""INSERT INTO finding_events
                    (id, project_id, finding_id, event_type, actor_id, run_id, related_run_ids,
                     fix_verification_id, suite_run_id, build_id, details, created_at)
                    VALUES (:event_id, :project_id, :finding_id, :event_type, :actor_id, :run_id, :related_run_ids,
                            :fix_verification_id, :suite_run_id, :build_id, CAST(:details AS jsonb), :created_at)
                    RETURNING id AS event_id, finding_events.*"""),
            {"event_id": event_id, "project_id": finding.project_id, "finding_id": finding.finding_id,
             "event_type": event_type, "actor_id": actor_id, "run_id": run_id,
             "related_run_ids": list(related_run_ids), "fix_verification_id": fix_verification_id,
             "suite_run_id": suite_run_id, "build_id": build_id,
             "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":")), "created_at": created_at},
        ).mappings().one()
        return _event_from_row(row)


def _mapping(value: object) -> dict[str, JsonValue]:
    if isinstance(value, Mapping):
        return cast(dict[str, JsonValue], dict(value))
    if isinstance(value, str):
        parsed = json.loads(value)
        return cast(dict[str, JsonValue], dict(parsed)) if isinstance(parsed, Mapping) else {}
    return {}


def _signals(value: object) -> dict[str, bool | None]:
    return TypeAdapter(dict[str, bool | None]).validate_python(_mapping(value))


def _json_value(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _finding_from_row(row: Mapping[str, object]) -> FindingRecord:
    return FindingRecord.model_validate({
        "finding_id": row["finding_id"], "project_id": row["project_id"], "fingerprint": str(row["fingerprint"]),
        "capsule_id": row["capsule_id"], "first_seen_build_id": row["first_seen_build_id"], "created_at": row["created_at"],
    })


def _event_from_row(row: Mapping[str, object]) -> FindingEventRecord:
    return FindingEventRecord.model_validate({
        "event_id": row["event_id"] if "event_id" in row else row["id"],
        "sequence": int(row["event_seq"]), "project_id": row["project_id"],
        "finding_id": row["finding_id"], "event_type": str(row["event_type"]),
        "actor_id": row["actor_id"], "run_id": row["run_id"], "related_run_ids": tuple(row["related_run_ids"] or ()),
        "fix_verification_id": row["fix_verification_id"], "suite_run_id": row["suite_run_id"], "build_id": row["build_id"],
        "details": _mapping(row["details"]), "created_at": row["created_at"],
    })


def _suite_run_from_row(row: Mapping[str, object]) -> RegressionSuiteRunRecord:
    return RegressionSuiteRunRecord.model_validate({
        "suite_run_id": row["id"], "project_id": row["project_id"], "suite_id": row["suite_id"], "build_id": row["build_id"],
        "state": str(row["state"]), "failed": bool(row["failed"]), "run_ids": tuple(row["run_ids"] or ()),
        "error_code": row["error_code"], "error_message": row["error_message"], "created_by": row["created_by"],
        "started_at": row["started_at"], "completed_at": row["completed_at"],
    })


def _verdict_from_row(row: Mapping[str, object]) -> StoredVerdictRecord:
    fired_value = row["fired_rules"]
    if isinstance(fired_value, str):
        fired_value = json.loads(fired_value)
    fired = tuple(str(item) for item in fired_value) if isinstance(fired_value, (list, tuple)) else ()
    return StoredVerdictRecord.model_validate({
        "verdict_id": row["id"], "project_id": row["project_id"], "run_id": row["run_id"],
        "verdict": str(row["verdict"]), "fired_rules": fired, "signals": _signals(row["signals"]),
        "completeness_score": float(row["completeness_score"]), "adjudicator_version": str(row["adjudicator_version"]),
        "supersedes_verdict_id": row["supersedes_verdict_id"], "created_at": row["created_at"],
    })
