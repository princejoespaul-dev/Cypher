"""Finding timeline queries and recurrence transition helper."""
from __future__ import annotations

from cypher.harness.phase5_errors import ForbiddenError, NotFoundError
from cypher.harness.phase5_models import Actor, FindingEventRecord, FindingEventType, FindingPage, ReplayRunRecord, Role
from uuid import UUID

from cypher.harness.phase5_ports import Phase5Repository


READ_ROLES = {Role.ADMIN, Role.REVIEWER, Role.ANALYST, Role.VIEWER}
WRITE_ROLES = {Role.ADMIN, Role.ANALYST}


class FindingsService:
    def __init__(self, repository: Phase5Repository) -> None:
        self._repo = repository

    def list(self, *, cursor: UUID | None, limit: int, actor: Actor) -> FindingPage:
        if actor.role not in READ_ROLES:
            raise ForbiddenError()
        if limit < 1 or limit > 100:
            from cypher.harness.phase5_errors import ValidationError
            raise ValidationError("pagination.limit_invalid", "limit must be between 1 and 100")
        return self._repo.list_findings(actor.project_id, cursor, limit)

    def timeline(self, *, finding_id: UUID, actor: Actor) -> tuple[FindingEventRecord, ...]:
        if actor.role not in READ_ROLES:
            raise ForbiddenError()
        if self._repo.get_finding(finding_id, actor.project_id) is None:
            raise NotFoundError("finding.not_found", "Finding was not found")
        return self._repo.get_finding_timeline(finding_id, actor.project_id)

    def observe_vulnerable_run(self, *, run: ReplayRunRecord, actor: Actor, suite_run_id: UUID | None = None) -> bool:
        """Open once; return whether a reintroduction was recorded.

        Recurrence is a stored state transition, never an AI inference. A previously
        fixed finding becomes reintroduced only when a later suite run is vulnerable.
        """
        if actor.role not in WRITE_ROLES:
            raise ForbiddenError()
        if run.project_id != actor.project_id or not run.sandbox_only:
            raise NotFoundError("replay.not_found", "Run was not found in this project")
        if run.verdict is None or not run.verdict.is_vulnerable:
            return False

        finding = self._repo.ensure_open_finding(run, actor.user_id)
        # Compare-and-append is retried if another worker records a transition after
        # our read. The finding row lock in the PostgreSQL adapter serializes writers.
        for _attempt in range(5):
            latest = self._repo.get_current_finding_event(finding.finding_id, actor.project_id)
            if latest is None:
                return False
            if latest.event_type.value == FindingEventType.REINTRODUCED.value:
                # Keep the CI gate red while the known recurrence remains unresolved,
                # without manufacturing a new event for every repeated run.
                return True
            if latest.event_type.value != FindingEventType.FIXED_VERIFIED.value:
                return False
            appended = self._repo.append_finding_event_if_state(
                finding=finding,
                expected_state=latest,
                event_type=FindingEventType.REINTRODUCED.value,
                actor_id=actor.user_id,
                run_id=run.run_id,
                related_run_ids=(run.run_id,),
                suite_run_id=suite_run_id,
                build_id=run.build_id,
                details={"fingerprint": run.capsule_fingerprint, "verdict": run.verdict.value},
            )
            if appended is not None:
                return True
        return False
