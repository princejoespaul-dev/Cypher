"""Regression-suite lifecycle and recurrence gating."""
from __future__ import annotations

from cypher.harness.findings import FindingsService
from cypher.harness.phase5_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from cypher.harness.phase5_models import (
    Actor,
    RegressionSuiteCreate,
    RegressionSuiteRecord,
    RegressionSuiteRunRecord,
    ReplayRunRecord,
    Role,
    SuiteState,
)
from uuid import UUID

from cypher.harness.phase5_ports import Clock, Phase5Repository, ReplayRunner, Rng, SystemClock, SystemRng


ANALYST_ROLES = {Role.ADMIN, Role.ANALYST}


class RegressionSuiteService:
    def __init__(self, repository: Phase5Repository, replay_runner: ReplayRunner, *, clock: Clock | None = None, rng: Rng | None = None) -> None:
        self._repo = repository
        self._runner = replay_runner
        self._clock = clock or SystemClock()
        self._rng = rng or SystemRng()
        self._findings = FindingsService(repository)

    def create(self, payload: RegressionSuiteCreate, actor: Actor) -> RegressionSuiteRecord:
        if actor.role not in ANALYST_ROLES:
            raise ForbiddenError()
        versions = []
        for version_id in payload.capsule_version_ids:
            version = self._repo.get_capsule_version(version_id, actor.project_id)
            if version is None:
                raise NotFoundError("capsule_version.not_found", "One or more capsule versions were not found")
            if version.status != "approved":
                raise ValidationError("regression_suite.capsule_not_approved", "Only approved capsule versions may enter a regression suite")
            versions.append(version)
        if len({v.target_id for v in versions}) != 1:
            raise ValidationError("regression_suite.target_mismatch", "All capsule versions in a suite must target the same target")
        record = RegressionSuiteRecord(
            suite_id=self._rng.new_uuid(),
            project_id=actor.project_id,
            name=payload.name,
            capsule_version_ids=payload.capsule_version_ids,
            created_by=actor.user_id,
            created_at=self._clock.now(),
        )
        self._repo.create_regression_suite(record, actor)
        return record

    def run(self, *, suite_id: UUID, build_id: UUID, repeats: int, actor: Actor) -> RegressionSuiteRunRecord:
        if actor.role not in ANALYST_ROLES:
            raise ForbiddenError()
        suite = self._repo.get_regression_suite(suite_id, actor.project_id)
        if suite is None:
            raise NotFoundError("regression_suite.not_found", "Regression suite was not found")
        build = self._repo.get_build(build_id, actor.project_id)
        if build is None:
            raise NotFoundError("build.not_found", "Build was not found")
        if not build.sandbox_only:
            raise ValidationError("env.not_sandbox", "Regression suites may run only against sandbox builds")
        versions = [self._repo.get_capsule_version(v, actor.project_id) for v in suite.capsule_version_ids]
        if any(v is None for v in versions):
            raise ConflictError("regression_suite.stale_capsule", "A suite capsule version is no longer available")
        if any(v.target_id != build.target_id for v in versions if v is not None):
            raise ValidationError("regression_suite.target_mismatch", "The selected build does not belong to the suite target")
        if repeats < 1 or repeats > 10:
            raise ValidationError("replay.repeat_limit", "repeats must be between 1 and 10")

        started = self._clock.now()
        suite_run = RegressionSuiteRunRecord(
            suite_run_id=self._rng.new_uuid(),
            project_id=actor.project_id,
            suite_id=suite.suite_id,
            build_id=build.build_id,
            state=SuiteState.RUNNING,
            failed=False,
            run_ids=(),
            created_by=actor.user_id,
            started_at=started,
        )
        self._repo.start_suite_run(suite_run, actor)
        completed_runs: list[ReplayRunRecord] = []
        failed = False

        try:
            for capsule_version_id in suite.capsule_version_ids:
                run = self._runner.replay(
                    capsule_version_id=capsule_version_id,
                    build_id=build.build_id,
                    project_id=actor.project_id,
                    repeats=repeats,
                )
                self._validate_runner_result(run, actor.project_id, build.build_id, capsule_version_id)
                completed_runs.append(run)
                if run.verdict is not None and run.verdict.is_vulnerable:
                    recurrence = self._findings.observe_vulnerable_run(run=run, actor=actor, suite_run_id=suite_run.suite_run_id)
                    failed = failed or recurrence

            final = suite_run.model_copy(update={
                "state": SuiteState.SUCCEEDED,
                "failed": failed,
                "run_ids": tuple(run.run_id for run in completed_runs),
                "completed_at": self._clock.now(),
            })
            self._repo.finish_suite_run(final, actor)
            return final
        except Exception as exc:
            # A worker/adapter error is a failed CI result, not a successful empty run.
            final = suite_run.model_copy(update={
                "state": SuiteState.FAILED,
                "failed": True,
                "run_ids": tuple(run.run_id for run in completed_runs),
                "error_code": getattr(exc, "code", "regression_suite.execution_failed"),
                "error_message": "Suite execution failed; consult redacted worker logs.",
                "completed_at": self._clock.now(),
            })
            self._repo.finish_suite_run(final, actor)
            raise

    @staticmethod
    def _validate_runner_result(run: ReplayRunRecord, project_id: UUID, build_id: UUID, capsule_version_id: UUID) -> None:
        if run.project_id != project_id or run.build_id != build_id or run.capsule_version_id != capsule_version_id:
            raise ConflictError("regression_suite.runner_scope_mismatch", "Replay runner returned a run outside the requested suite scope")
        if not run.sandbox_only:
            raise ValidationError("env.not_sandbox", "Replay runner returned a non-sandbox run")
        if not run.run_state.is_finished:
            raise ConflictError("regression_suite.run_not_finished", "Replay runner must return a finished run")
