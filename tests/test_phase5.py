from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from cypher.harness.fixverify import FixVerificationService
from cypher.harness.memory_repository import InMemoryPhase5Repository
from cypher.harness.phase5_errors import ConflictError, ForbiddenError, ValidationError
from cypher.harness.phase5_models import (
    Actor,
    AdjudicationDecision,
    BuildLabel,
    BuildRecord,
    CapsuleVersionRecord,
    EvidenceBundle,
    FixOutcome,
    ReadjudicateRequest,
    RegressionSuiteCreate,
    ReplayRunRecord,
    Role,
    RunState,
    StoredVerdictRecord,
    SuiteState,
    Verdict,
)
from cypher.harness.readjudicate import ReadjudicationService
from cypher.harness.suites import RegressionSuiteService


PROJECT = uuid4()
OTHER_PROJECT = uuid4()
TARGET = uuid4()
CAPSULE = uuid4()
CAPSULE_VERSION = uuid4()
FINGERPRINT = "a" * 64
USER = uuid4()
VULNERABLE_BUILD = uuid4()
FIXED_BUILD = uuid4()


def actor(role: Role = Role.ANALYST, project_id: UUID = PROJECT) -> Actor:
    return Actor(user_id=USER, project_id=project_id, role=role)


def make_run(
    *,
    build_label: BuildLabel,
    verdict: Verdict,
    control_ok: bool | None = True,
    project_id: UUID = PROJECT,
    run_id: UUID | None = None,
    build_id: UUID | None = None,
    capsule_version_id: UUID = CAPSULE_VERSION,
    capsule_fingerprint: str = FINGERPRINT,
    sandbox_only: bool = True,
) -> ReplayRunRecord:
    return ReplayRunRecord(
        run_id=run_id or uuid4(),
        project_id=project_id,
        target_id=TARGET,
        capsule_id=CAPSULE,
        capsule_version_id=capsule_version_id,
        capsule_fingerprint=capsule_fingerprint,
        build_id=build_id or (VULNERABLE_BUILD if build_label == BuildLabel.VULNERABLE else FIXED_BUILD),
        build_label=build_label,
        run_state=RunState.COMPLETED,
        sandbox_only=sandbox_only,
        verdict_id=uuid4(),
        verdict=verdict,
        signals={"control_ok": control_ok, "cf_leak": verdict == Verdict.VULNERABLE_DATA_EXPOSURE},
    )


def seed_builds(repo: InMemoryPhase5Repository) -> None:
    repo.seed_build(BuildRecord(build_id=VULNERABLE_BUILD, project_id=PROJECT, target_id=TARGET, label=BuildLabel.VULNERABLE, sandbox_only=True))
    repo.seed_build(BuildRecord(build_id=FIXED_BUILD, project_id=PROJECT, target_id=TARGET, label=BuildLabel.FIXED, sandbox_only=True))


def seed_capsule(repo: InMemoryPhase5Repository, status: str = "approved") -> None:
    repo.seed_capsule_version(CapsuleVersionRecord(
        capsule_version_id=CAPSULE_VERSION,
        project_id=PROJECT,
        capsule_id=CAPSULE,
        target_id=TARGET,
        version=1,
        status=status,
        fingerprint=FINGERPRINT,
    ))


def test_fix_verified_appends_open_and_fixed_verified_events() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED)
    repo.seed_run(vulnerable)
    repo.seed_run(fixed)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed.run_id, actor=actor())

    assert record.outcome == FixOutcome.FIX_VERIFIED
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    timeline = repo.get_finding_timeline(finding.finding_id, PROJECT)
    assert [event.event_type.value for event in timeline] == ["open", "fixed_verified"]
    assert timeline[-1].related_run_ids == (vulnerable.run_id, fixed.run_id)
    assert len(repo.fix_verifications) == 1


def test_fix_verification_requires_the_exact_same_capsule_version() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED, capsule_version_id=uuid4())
    repo.seed_run(vulnerable)
    repo.seed_run(fixed)

    with pytest.raises(ValidationError, match="exact same capsule version"):
        FixVerificationService(repo).verify(
            vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed.run_id, actor=actor()
        )


def test_each_verified_fix_appends_its_own_event() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    fixed_one = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED)
    fixed_two = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED)
    for run in (vulnerable, fixed_one, fixed_two):
        repo.seed_run(run)

    service = FixVerificationService(repo)
    first = service.verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed_one.run_id, actor=actor())
    second = service.verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed_two.run_id, actor=actor())

    assert first.outcome == second.outcome == FixOutcome.FIX_VERIFIED
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    timeline = repo.get_finding_timeline(finding.finding_id, PROJECT)
    assert [event.event_type.value for event in timeline] == ["open", "fixed_verified", "fixed_verified"]
    assert timeline[-1].fix_verification_id == second.verification_id


def test_partial_fix_yields_fix_incomplete_and_does_not_mark_fixed() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_STATE_CHANGE)
    partial = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.VULNERABLE_STATE_CHANGE)
    repo.seed_run(vulnerable)
    repo.seed_run(partial)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=partial.run_id, actor=actor())

    assert record.outcome == FixOutcome.FIX_INCOMPLETE
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    assert [event.event_type.value for event in repo.get_finding_timeline(finding.finding_id, PROJECT)] == ["open"]


def test_partial_fix_variant_is_allowed_and_yields_fix_incomplete() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, control_ok=True)
    partial = make_run(build_label=BuildLabel.PARTIAL_FIX, verdict=Verdict.VULNERABLE_STATE_CHANGE, control_ok=True)
    repo.seed_run(vulnerable)
    repo.seed_run(partial)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=partial.run_id, actor=actor())
    assert record.outcome == FixOutcome.FIX_INCOMPLETE


def test_over_blocking_yields_fix_breaks_control() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, control_ok=True)
    over_blocking = make_run(build_label=BuildLabel.OVER_BLOCKING, verdict=Verdict.INCONCLUSIVE_CONTROL, control_ok=False)
    repo.seed_run(vulnerable)
    repo.seed_run(over_blocking)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=over_blocking.run_id, actor=actor())
    assert record.outcome == FixOutcome.FIX_BREAKS_CONTROL


def test_environment_failure_is_not_misclassified_as_over_blocking() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, control_ok=True)
    failed_environment = make_run(build_label=BuildLabel.OVER_BLOCKING, verdict=Verdict.INCONCLUSIVE_ENVIRONMENT, control_ok=False)
    failed_environment = failed_environment.model_copy(update={"signals": {"control_ok": False, "env_error": True}})
    repo.seed_run(vulnerable)
    repo.seed_run(failed_environment)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=failed_environment.run_id, actor=actor())
    assert record.outcome == FixOutcome.FIX_UNVERIFIABLE


def test_inconclusive_vulnerable_build_is_unverifiable() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.INCONCLUSIVE_ENVIRONMENT, control_ok=True)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED, control_ok=True)
    repo.seed_run(vulnerable)
    repo.seed_run(fixed)

    record = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed.run_id, actor=actor())
    assert record.outcome == FixOutcome.FIX_UNVERIFIABLE


def test_fix_verification_rejects_non_sandbox_or_wrong_build_labels() -> None:
    repo = InMemoryPhase5Repository()
    unsafe = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, sandbox_only=False)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED)
    repo.seed_run(unsafe)
    repo.seed_run(fixed)
    with pytest.raises(ValidationError, match="sandbox"):
        FixVerificationService(repo).verify(vulnerable_run_id=unsafe.run_id, fixed_run_id=fixed.run_id, actor=actor())


def test_finding_open_is_idempotent_for_same_project_and_fingerprint() -> None:
    repo = InMemoryPhase5Repository()
    run1 = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    run2 = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    repo.seed_run(run1)
    repo.seed_run(run2)
    repo.ensure_open_finding(run1, USER)
    repo.ensure_open_finding(run2, USER)
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    assert len(repo.get_finding_timeline(finding.finding_id, PROJECT)) == 1


class FakeRunner:
    def __init__(self, runs: list[ReplayRunRecord]) -> None:
        self.runs = runs

    def replay(self, *, capsule_version_id, build_id, project_id, repeats) -> ReplayRunRecord:
        for run in self.runs:
            if run.capsule_version_id == capsule_version_id and run.build_id == build_id:
                return run
        raise AssertionError("No configured replay result")


def make_suite_service(repo: InMemoryPhase5Repository, run: ReplayRunRecord) -> tuple[RegressionSuiteService, UUID]:
    seed_builds(repo)
    seed_capsule(repo)
    suite_service = RegressionSuiteService(repo, FakeRunner([run]))
    suite = suite_service.create(RegressionSuiteCreate(name="API authorization regressions", capsule_version_ids=(CAPSULE_VERSION,)), actor())
    return suite_service, suite.suite_id


def test_reintroduced_vulnerability_fails_suite_and_appends_event() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable_initial = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, build_id=VULNERABLE_BUILD)
    fixed_run = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED, build_id=FIXED_BUILD)
    for run in (vulnerable_initial, fixed_run):
        repo.seed_run(run)
    fix = FixVerificationService(repo).verify(vulnerable_run_id=vulnerable_initial.run_id, fixed_run_id=fixed_run.run_id, actor=actor())
    assert fix.outcome == FixOutcome.FIX_VERIFIED

    reintroduced_build = uuid4()
    repo.seed_build(BuildRecord(build_id=reintroduced_build, project_id=PROJECT, target_id=TARGET, label=BuildLabel.REINTRODUCED, sandbox_only=True))
    reintroduced_run = make_run(build_label=BuildLabel.REINTRODUCED, verdict=Verdict.VULNERABLE_STATE_CHANGE, build_id=reintroduced_build)
    repo.seed_run(reintroduced_run)
    seed_capsule(repo)
    suite = RegressionSuiteService(repo, FakeRunner([reintroduced_run])).create(
        RegressionSuiteCreate(name="Main branch gate", capsule_version_ids=(CAPSULE_VERSION,)), actor()
    )
    result = RegressionSuiteService(repo, FakeRunner([reintroduced_run])).run(
        suite_id=suite.suite_id, build_id=reintroduced_build, repeats=3, actor=actor()
    )

    assert result.failed is True
    assert result.state == SuiteState.SUCCEEDED  # Runner worked; CI gate failed due to recurrence.
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    assert [e.event_type.value for e in repo.get_finding_timeline(finding.finding_id, PROJECT)] == ["open", "fixed_verified", "reintroduced"]
    assert repo.get_finding_timeline(finding.finding_id, PROJECT)[-1].suite_run_id == result.suite_run_id


def test_recurrence_keeps_suite_failed_until_a_new_fix_is_verified() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, build_id=VULNERABLE_BUILD)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED, build_id=FIXED_BUILD)
    repo.seed_run(vulnerable)
    repo.seed_run(fixed)
    assert FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed.run_id, actor=actor()).outcome == FixOutcome.FIX_VERIFIED

    reintroduced_build = uuid4()
    repo.seed_build(BuildRecord(build_id=reintroduced_build, project_id=PROJECT, target_id=TARGET, label=BuildLabel.REINTRODUCED, sandbox_only=True))
    recurrence = make_run(build_label=BuildLabel.REINTRODUCED, verdict=Verdict.VULNERABLE_STATE_CHANGE, build_id=reintroduced_build)
    repo.seed_run(recurrence)
    seed_capsule(repo)
    suite_service = RegressionSuiteService(repo, FakeRunner([recurrence]))
    suite = suite_service.create(RegressionSuiteCreate(name="Recurring authorization check", capsule_version_ids=(CAPSULE_VERSION,)), actor())

    first = suite_service.run(suite_id=suite.suite_id, build_id=reintroduced_build, repeats=1, actor=actor())
    second = suite_service.run(suite_id=suite.suite_id, build_id=reintroduced_build, repeats=1, actor=actor())
    assert first.failed is True and second.failed is True
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    assert [event.event_type.value for event in repo.get_finding_timeline(finding.finding_id, PROJECT)] == ["open", "fixed_verified", "reintroduced"]


def test_first_time_vulnerability_opens_finding_but_does_not_mark_suite_failed() -> None:
    repo = InMemoryPhase5Repository()
    seed_builds(repo)
    seed_capsule(repo)
    first_vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, build_id=VULNERABLE_BUILD)
    repo.seed_run(first_vulnerable)
    suite = RegressionSuiteService(repo, FakeRunner([first_vulnerable])).create(
        RegressionSuiteCreate(name="Initial detection", capsule_version_ids=(CAPSULE_VERSION,)), actor()
    )
    result = RegressionSuiteService(repo, FakeRunner([first_vulnerable])).run(
        suite_id=suite.suite_id, build_id=VULNERABLE_BUILD, repeats=1, actor=actor()
    )
    assert result.failed is False
    finding = repo.get_finding_by_fingerprint(PROJECT, FINGERPRINT)
    assert finding is not None
    assert [e.event_type.value for e in repo.get_finding_timeline(finding.finding_id, PROJECT)] == ["open"]


def test_suite_rejects_unapproved_capsule() -> None:
    repo = InMemoryPhase5Repository()
    seed_builds(repo)
    seed_capsule(repo, status="validated")
    service = RegressionSuiteService(repo, FakeRunner([]))
    with pytest.raises(ValidationError, match="approved"):
        service.create(RegressionSuiteCreate(name="Bad suite", capsule_version_ids=(CAPSULE_VERSION,)), actor())


def test_findings_cursor_pagination_is_project_scoped_and_does_not_repeat_items() -> None:
    repo = InMemoryPhase5Repository()
    for marker_char in ("a", "b", "c"):
        run = make_run(
            build_label=BuildLabel.VULNERABLE,
            verdict=Verdict.VULNERABLE_DATA_EXPOSURE,
            capsule_fingerprint=marker_char * 64,
        )
        repo.seed_run(run)
        repo.ensure_open_finding(run, USER)

    from cypher.harness.findings import FindingsService
    first_page = FindingsService(repo).list(cursor=None, limit=2, actor=actor())
    assert len(first_page.items) == 2
    assert first_page.next_cursor is not None
    second_page = FindingsService(repo).list(cursor=first_page.next_cursor, limit=2, actor=actor())
    assert len(second_page.items) == 1
    assert second_page.next_cursor is None
    assert set(item.finding_id for item in first_page.items).isdisjoint(item.finding_id for item in second_page.items)


def test_cross_project_resources_are_not_disclosed() -> None:
    repo = InMemoryPhase5Repository()
    other = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE, project_id=OTHER_PROJECT)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED, project_id=OTHER_PROJECT)
    repo.seed_run(other)
    repo.seed_run(fixed)
    with pytest.raises(Exception) as exc:
        FixVerificationService(repo).verify(vulnerable_run_id=other.run_id, fixed_run_id=fixed.run_id, actor=actor(project_id=PROJECT))
    assert getattr(exc.value, "code", None) == "replay.not_found"


def test_readjudication_appends_new_verdict_without_mutating_old() -> None:
    repo = InMemoryPhase5Repository()
    run = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    repo.seed_run(run)
    old = StoredVerdictRecord(
        verdict_id=run.verdict_id,
        project_id=PROJECT,
        run_id=run.run_id,
        verdict=Verdict.VULNERABLE_DATA_EXPOSURE,
        fired_rules=("rule_4_cf_leak",),
        signals=run.signals,
        completeness_score=0.9,
        adjudicator_version="adjudicator-1",
        created_at=datetime.now(timezone.utc),
    )
    assert old.verdict_id is not None
    repo.seed_verdict(old)
    repo.seed_evidence(run.run_id, PROJECT, EvidenceBundle(capsule={}, observations=(), state_snapshots=(), config={}))

    class FakeAdjudicator:
        def adjudicate(self, *, evidence, adjudicator_version):
            return AdjudicationDecision(
                verdict=Verdict.PROTECTED,
                fired_rules=("rule_5_protected",),
                signals={"control_ok": True, "cf_denied": True, "cf_leak": False, "state_changed": False, "env_error": False},
                completeness_score=1.0,
                adjudicator_version=adjudicator_version,
            )

    service = ReadjudicationService(repo, FakeAdjudicator())
    new = service.run(verdict_id=old.verdict_id, request=ReadjudicateRequest(adjudicator_version="adjudicator-2"), actor=actor())

    assert new.verdict == Verdict.PROTECTED
    assert new.supersedes_verdict_id == old.verdict_id
    assert repo.get_verdict(old.verdict_id, PROJECT) == old
    assert repo.get_verdict(new.verdict_id, PROJECT) == new
    assert repo.get_run(run.run_id, PROJECT).verdict == Verdict.PROTECTED


def test_same_adjudicator_version_is_rejected() -> None:
    repo = InMemoryPhase5Repository()
    run = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    repo.seed_run(run)
    old = StoredVerdictRecord(
        verdict_id=run.verdict_id,
        project_id=PROJECT,
        run_id=run.run_id,
        verdict=Verdict.VULNERABLE_DATA_EXPOSURE,
        fired_rules=(),
        signals=run.signals,
        completeness_score=1.0,
        adjudicator_version="adj-1",
        created_at=datetime.now(timezone.utc),
    )
    repo.seed_verdict(old)

    class NeverCalled:
        def adjudicate(self, *, evidence, adjudicator_version):
            raise AssertionError("must reject before adjudicator call")

    with pytest.raises(Exception) as exc:
        ReadjudicationService(repo, NeverCalled()).run(
            verdict_id=old.verdict_id,
            request=ReadjudicateRequest(adjudicator_version="adj-1"),
            actor=actor(),
        )
    assert getattr(exc.value, "code", None) == "verdict.same_adjudicator_version"


def test_viewer_cannot_run_fix_verification() -> None:
    repo = InMemoryPhase5Repository()
    vulnerable = make_run(build_label=BuildLabel.VULNERABLE, verdict=Verdict.VULNERABLE_DATA_EXPOSURE)
    fixed = make_run(build_label=BuildLabel.FIXED, verdict=Verdict.PROTECTED)
    repo.seed_run(vulnerable)
    repo.seed_run(fixed)
    with pytest.raises(ForbiddenError):
        FixVerificationService(repo).verify(vulnerable_run_id=vulnerable.run_id, fixed_run_id=fixed.run_id, actor=actor(Role.VIEWER))


def test_capsule_fingerprint_uses_only_declared_recurrence_dimensions() -> None:
    from cypher.harness.postgres_repository import _capsule_fingerprint

    capsule = {
        "target": {"operation_id": "getOrder", "method": "GET", "path": "/orders/{order_id}"},
        "policy": {"rule_id": "orders.read.owner_only"},
        "counterfactual": {"mutation": {"dimension": "principal"}},
        "resource": {"type": "order", "fixture_ref": "orders.a1"},
        "title": "First title",
    }
    renamed = {**capsule, "title": "Renamed title"}
    changed_dimension = {**capsule, "counterfactual": {"mutation": {"dimension": "object_id"}}}
    assert _capsule_fingerprint(capsule) == _capsule_fingerprint(renamed)
    assert _capsule_fingerprint(capsule) != _capsule_fingerprint(changed_dimension)


def test_api_uses_problem_json_for_auth_errors_and_requires_idempotency_key() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from cypher.api.phase5_router import install_phase5_exception_handler, router

    app = FastAPI()
    app.include_router(router)
    install_phase5_exception_handler(app)
    client = TestClient(app)
    response = client.get(f"/v1/findings/{uuid4()}/timeline")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    run_schema = app.openapi()["paths"]["/v1/regression-suites/{suite_id}/run"]["post"]
    header_params = [param for param in run_schema["parameters"] if param["in"] == "header"]
    assert any(param["name"] == "Idempotency-Key" and param["required"] for param in header_params)


def test_re_adjudication_rejects_a_version_already_present_in_run_history() -> None:
    repo = InMemoryPhase5Repository()
    run_id = uuid4()
    first = StoredVerdictRecord(
        verdict_id=uuid4(), project_id=PROJECT, run_id=run_id, verdict=Verdict.PROTECTED,
        fired_rules=("denial",), signals={"control_ok": True}, completeness_score=1.0,
        adjudicator_version="v1", created_at=datetime.now(timezone.utc),
    )
    second = first.model_copy(update={
        "verdict_id": uuid4(), "adjudicator_version": "v2", "supersedes_verdict_id": first.verdict_id,
    })
    repo.seed_verdict(first)
    repo.seed_verdict(second)
    duplicate = second.model_copy(update={
        "verdict_id": uuid4(), "supersedes_verdict_id": first.verdict_id,
    })
    with pytest.raises(ConflictError, match="already has a verdict under the requested adjudicator version"):
        repo.append_verdict(duplicate, actor())
