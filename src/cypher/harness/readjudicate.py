"""Append-only re-adjudication of stored evidence under a new rule version."""
from __future__ import annotations


from uuid import UUID

from cypher.harness.phase5_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from cypher.harness.phase5_models import Actor, ReadjudicateRequest, Role, StoredVerdictRecord
from cypher.harness.phase5_ports import Clock, Phase5Repository, PureAdjudicator, Rng, SystemClock, SystemRng


class ReadjudicationService:
    def __init__(self, repository: Phase5Repository, adjudicator: PureAdjudicator, *, clock: Clock | None = None, rng: Rng | None = None) -> None:
        self._repo = repository
        self._adjudicator = adjudicator
        self._clock = clock or SystemClock()
        self._rng = rng or SystemRng()

    def run(self, *, verdict_id: UUID, request: ReadjudicateRequest, actor: Actor) -> StoredVerdictRecord:
        if actor.role not in {Role.ADMIN, Role.ANALYST}:
            raise ForbiddenError()
        prior = self._repo.get_verdict(verdict_id, actor.project_id)
        if prior is None:
            raise NotFoundError("verdict.not_found", "Verdict was not found")
        if prior.adjudicator_version == request.adjudicator_version:
            raise ConflictError("verdict.same_adjudicator_version", "Choose a different adjudicator version to create a re-adjudication record")
        evidence = self._repo.get_evidence_bundle(prior.run_id, actor.project_id)
        if evidence is None:
            raise ConflictError("evidence.missing", "Stored redacted evidence required for re-adjudication is incomplete")

        decision = self._adjudicator.adjudicate(evidence=evidence, adjudicator_version=request.adjudicator_version)
        if decision.adjudicator_version != request.adjudicator_version:
            raise ValidationError("adjudicator.version_mismatch", "Adjudicator returned a version different from the requested version")

        record = StoredVerdictRecord(
            verdict_id=self._rng.new_uuid(),
            project_id=actor.project_id,
            run_id=prior.run_id,
            verdict=decision.verdict,
            fired_rules=decision.fired_rules,
            signals=decision.signals,
            completeness_score=decision.completeness_score,
            adjudicator_version=decision.adjudicator_version,
            supersedes_verdict_id=prior.verdict_id,
            created_at=self._clock.now(),
        )
        self._repo.append_verdict(record, actor)
        return record
