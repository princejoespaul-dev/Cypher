"""Deterministic fix-verification classification and service."""
from __future__ import annotations

from cypher.harness.phase5_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from cypher.harness.phase5_models import (
    Actor,
    BuildLabel,
    FixOutcome,
    FixVerificationRecord,
    ReplayRunRecord,
    Role,
    Verdict,
)
from uuid import UUID

from cypher.harness.phase5_ports import Clock, Phase5Repository, Rng, SystemClock, SystemRng


ANALYST_ROLES = {Role.ADMIN, Role.ANALYST}


def classify_fix(vulnerable: ReplayRunRecord, fixed: ReplayRunRecord) -> FixOutcome:
    """Classify a candidate fix using only already-stored deterministic evidence.

    The vulnerable build must first reproduce the finding. An environmental or flaky
    failure cannot be labelled over-blocking. Once reproduction is established, a
    fixed build whose owner control failed is ``FIX_BREAKS_CONTROL`` even though its
    adjudicator result is commonly ``INCONCLUSIVE_CONTROL``.
    """
    vuln_control = vulnerable.signals.get("control_ok")
    fixed_control = fixed.signals.get("control_ok")

    if (
        vulnerable.verdict is None
        or not vulnerable.verdict.is_vulnerable
        or vulnerable.verdict.is_inconclusive
        or vuln_control is not True
        or vulnerable.signals.get("env_error") is True
    ):
        return FixOutcome.FIX_UNVERIFIABLE

    if (
        fixed.verdict is None
        or fixed.signals.get("env_error") is True
        or fixed.verdict in {Verdict.INCONCLUSIVE_ENVIRONMENT, Verdict.INCONCLUSIVE_FLAKY}
    ):
        return FixOutcome.FIX_UNVERIFIABLE

    if fixed_control is False:
        return FixOutcome.FIX_BREAKS_CONTROL

    if fixed_control is not True or fixed.verdict.is_inconclusive:
        return FixOutcome.FIX_UNVERIFIABLE

    if fixed.verdict.is_vulnerable:
        return FixOutcome.FIX_INCOMPLETE

    if fixed.verdict == Verdict.PROTECTED and fixed.build_label == BuildLabel.FIXED:
        return FixOutcome.FIX_VERIFIED

    return FixOutcome.FIX_UNVERIFIABLE


class FixVerificationService:
    def __init__(self, repository: Phase5Repository, *, clock: Clock | None = None, rng: Rng | None = None) -> None:
        self._repo = repository
        self._clock = clock or SystemClock()
        self._rng = rng or SystemRng()

    def verify(self, *, vulnerable_run_id: UUID, fixed_run_id: UUID, actor: Actor) -> FixVerificationRecord:
        if actor.role not in ANALYST_ROLES:
            raise ForbiddenError()

        vulnerable = self._repo.get_run(vulnerable_run_id, actor.project_id)
        fixed = self._repo.get_run(fixed_run_id, actor.project_id)
        if vulnerable is None or fixed is None:
            # Do not disclose whether a run exists in another project.
            raise NotFoundError("replay.not_found", "One or more replay runs were not found")

        self._validate_pair(vulnerable, fixed)

        # The first vulnerable observation opens a finding even if later fix checks
        # turn out inconclusive. Opening is idempotent and fingerprint scoped.
        if vulnerable.verdict is not None and vulnerable.verdict.is_vulnerable:
            finding = self._repo.ensure_open_finding(vulnerable, actor.user_id)
        else:
            finding = self._repo.get_finding_by_fingerprint(actor.project_id, vulnerable.capsule_fingerprint)

        outcome = classify_fix(vulnerable, fixed)
        record = FixVerificationRecord(
            verification_id=self._rng.new_uuid(),
            project_id=actor.project_id,
            fingerprint=vulnerable.capsule_fingerprint,
            capsule_version_id=vulnerable.capsule_version_id,
            vulnerable_build_id=vulnerable.build_id,
            fixed_build_id=fixed.build_id,
            vulnerable_run_id=vulnerable.run_id,
            fixed_run_id=fixed.run_id,
            outcome=outcome,
            created_by=actor.user_id,
            created_at=self._clock.now(),
        )

        self._repo.save_fix_verification(record, actor, finding=finding)
        return record

    @staticmethod
    def _validate_pair(vulnerable: ReplayRunRecord, fixed: ReplayRunRecord) -> None:
        if vulnerable.run_id == fixed.run_id:
            raise ValidationError("fix_verification.same_run", "Vulnerable and fixed run IDs must differ")
        if vulnerable.project_id != fixed.project_id:
            raise NotFoundError("replay.not_found", "One or more replay runs were not found")
        if vulnerable.target_id != fixed.target_id:
            raise ValidationError("fix_verification.target_mismatch", "Both runs must target the same target")
        if vulnerable.capsule_version_id != fixed.capsule_version_id:
            raise ValidationError("fix_verification.capsule_version_mismatch", "Both runs must use the exact same capsule version")
        if vulnerable.capsule_fingerprint != fixed.capsule_fingerprint:
            raise ValidationError("fix_verification.capsule_mismatch", "Both runs must use the same capsule fingerprint")
        if vulnerable.build_label != BuildLabel.VULNERABLE:
            raise ValidationError("fix_verification.expected_vulnerable_build", "First run must use a build labelled 'vulnerable'")
        if fixed.build_label not in {BuildLabel.FIXED, BuildLabel.PARTIAL_FIX, BuildLabel.OVER_BLOCKING}:
            raise ValidationError(
                "fix_verification.expected_candidate_build",
                "Second run must use a build labelled 'fixed', 'partial_fix', or 'over_blocking'",
            )
        if not vulnerable.sandbox_only or not fixed.sandbox_only:
            raise ValidationError("env.not_sandbox", "Fix verification is permitted only on sandbox builds")
        if not vulnerable.run_state.is_finished or not fixed.run_state.is_finished:
            raise ConflictError("replay.not_finished", "Both replay runs must be finished before fix verification")
        if vulnerable.verdict is None or fixed.verdict is None:
            raise ConflictError("verdict.missing", "Both replay runs must have a stored verdict")
