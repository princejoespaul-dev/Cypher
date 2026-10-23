from __future__ import annotations

from uuid import uuid4

import pytest

from cypher.core.auth import Role
from cypher.core.errors import Conflict, Forbidden
from cypher.experiments.metrics import VerdictSample, calculate_verdict_metrics
from cypher.experiments.models import ExperimentConfig
from cypher.experiments.runner import ExperimentRunner, verify_export
from cypher.guidance.llm.fake import FakeLLMClient
from cypher.guidance.pipeline import GuidanceService, SuggestRequest, SuggestionState
from cypher.capsules.validators import ValidationContext
from cypher.history.models import OutcomeLabel, ReviewStatus
from cypher.history.service import HistoryService
from cypher.harness.phase5_models import Verdict


def raw_capsule(policy_id):
    return {"aic_version":"1.0", "title":"Owner only order read", "vuln_class":"BOLA",
            "target":{"operation_id":"getOrder","method":"GET","path":"/orders/{order_id}"},
            "policy":{"policy_version_id":str(policy_id),"rule_id":"orders.read.owner_only"},
            "principals":{"owner":"user_a","other":"user_b"},
            "resource":{"type":"order","fixture_ref":"orders.a1"},
            "positive_control":{"as":"user_a","request":{"path_params":{"order_id":"$resource.id"}},
                                "expect":{"status_in":[200],"fingerprint_fields":["$.customer_email"]}},
            "counterfactual":{"mutation":{"dimension":"principal","from":"user_a","to":"user_b"},
                              "expect_denied":{"status_in":[401,403,404],"leak_check":"fingerprint_absent"}},
            "state_oracle":{"enabled":True,"probes":["orders_row_hash"],"expect":"unchanged"},
            "safety":{"sandbox_only":True,"destructive":False}, "provenance":{"authored_by":"human","suggestion_id":None}}


def test_guidance_suggestions_require_reviewer_and_dry_run():
    project_id, target_id, requester, reviewer, policy_id = uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
    context = ValidationContext(True, frozenset({"getOrder"}), frozenset({"user_a","user_b"}),
                                frozenset({"orders.a1"}), frozenset({policy_id}), frozenset({"orders.read.owner_only"}))
    client = FakeLLMClient([{"capsules":[raw_capsule(policy_id)]}])
    service = GuidanceService(llm=client, validation_context=lambda *_: context, dry_run=lambda _aic: True)
    batch = service.suggest_capsules(SuggestRequest(project_id, requester, target_id, ("getOrder",),
        {"operations":[{"operation_id":"getOrder","method":"GET","path":"/orders/{order_id}"}], "principals":["user_a","user_b"], "fixtures":["orders.a1"]}, 1))
    assert batch.accepted_count == 1
    suggestion = batch.suggestions[0]
    assert suggestion.state == SuggestionState.PENDING_REVIEW
    assert suggestion.validated_payload["provenance"]["authored_by"] == "guidance"
    assert suggestion.validated_payload["provenance"]["suggestion_id"] == str(suggestion.suggestion_id)
    with pytest.raises(Forbidden):
        service.decide(suggestion.suggestion_id, project_id=project_id, reviewer_id=requester, reviewer_role=Role.REVIEWER, approve=True, comment="self approval")
    approved = service.decide(suggestion.suggestion_id, project_id=project_id, reviewer_id=reviewer, reviewer_role=Role.REVIEWER, approve=True, comment="dry run passed")
    assert approved.state == SuggestionState.APPROVED
    assert approved.approved_capsule is not None


def test_guidance_rejects_operation_outside_context():
    project_id, target_id, requester, policy_id = uuid4(), uuid4(), uuid4(), uuid4()
    context = ValidationContext(True, frozenset({"getOrder"}), frozenset({"user_a","user_b"}),
                                frozenset({"orders.a1"}), frozenset({policy_id}), frozenset({"orders.read.owner_only"}))
    output = raw_capsule(policy_id); output["target"]["operation_id"] = "deleteUsers"
    client = FakeLLMClient([{"capsules":[output]}])
    service = GuidanceService(llm=client, validation_context=lambda *_: context, dry_run=lambda _aic: True)
    batch = service.suggest_capsules(SuggestRequest(project_id, requester, target_id, ("getOrder",),
        {"operations":[{"operation_id":"getOrder","method":"GET","path":"/orders/{order_id}"}]}, 1))
    assert batch.rejected_count == 1
    assert batch.suggestions[0].state == SuggestionState.REJECTED_BY_VALIDATOR


def test_history_retrieves_reviewed_only_and_freezes_reviewed_case():
    service = HistoryService()
    project_id, finding_id, reviewer = uuid4(), uuid4(), uuid4()
    draft = service.draft_case(project_id=project_id, finding_id=finding_id, vuln_class="BOLA", mutation_dimension="principal",
        method="GET", resource_type="order", policy_rule_type="owner_only", pattern_summary="order read failed to check owner",
        fix_pattern="enforce owner on each resource read", evidence_ids=("evidence-1",), finding_event_ids=(uuid4(),))
    assert service.retrieve(project_id=project_id, vuln_class="BOLA", mutation_dimension="principal", method="GET",
                           resource_type="order", query_text="owner order read") == ()
    reviewed = service.review_case(case_id=draft.case_id, project_id=project_id, label=OutcomeLabel.FIX_VERIFIED, reviewer_id=reviewer)
    assert reviewed.review_status == ReviewStatus.REVIEWED
    retrieved = service.retrieve(project_id=project_id, vuln_class="BOLA", mutation_dimension="principal", method="GET",
                                 resource_type="order", query_text="owner order read")
    assert len(retrieved) == 1 and retrieved[0]["case_id"] == str(draft.case_id)
    with pytest.raises(Conflict):
        service.review_case(case_id=draft.case_id, project_id=project_id, label=OutcomeLabel.RECURRED, reviewer_id=reviewer)


def test_history_recommendation_rejects_invented_case_or_evidence_citations():
    service = HistoryService(capsule_drafter=lambda _ctx: ({"capsule":{"title":"draft"},"case_ids":[str(uuid4())],"evidence_ids":["made-up"]},))
    project_id, finding_id, reviewer = uuid4(), uuid4(), uuid4()
    case = service.draft_case(project_id=project_id, finding_id=finding_id, vuln_class="BOLA", mutation_dimension="principal",
        method="GET", resource_type="order", policy_rule_type="owner_only", pattern_summary="order read owner check",
        fix_pattern="use ownership control", evidence_ids=("e-1",), finding_event_ids=(uuid4(),))
    service.review_case(case_id=case.case_id, project_id=project_id, label=OutcomeLabel.FIX_VERIFIED, reviewer_id=reviewer)
    rec = service.recommend(project_id=project_id, query={"vuln_class":"BOLA","mutation_dimension":"principal","method":"GET","resource_type":"order","query_text":"owner order"},
                            available_evidence_ids={"e-1"})
    assert rec.state == "rejected_by_validator"
    assert rec.validation_errors and rec.capsule_drafts == ()


def test_experiment_metrics_and_export_are_reproducible(tmp_path):
    rows = [VerdictSample("a", True, Verdict.VULNERABLE_DATA_EXPOSURE, False),
            VerdictSample("b", False, Verdict.PROTECTED, True),
            VerdictSample("c", True, Verdict.INCONCLUSIVE_CONTROL, False)]
    metrics = calculate_verdict_metrics(rows)
    assert metrics["precision"] == 1.0 and metrics["recall"] == 1.0 and metrics["abstention_rate"] == 1/3
    config = ExperimentConfig(experiment_id=uuid4(), name="small check", arms=("A","C"), seeds=(1,2), repeat_count=2,
                              adjudicator_version="1.0.0", target_ids=(uuid4(),), ground_truth_sha256="a"*64)
    runner = ExperimentRunner(repository_root=tmp_path)
    manifest = runner.create_manifest(config, image_digests={"ref":"sha256:"+"1"*64}, prompt_hashes={}, model_ids={},
                                      embedding_version=None, case_library_snapshot_id=None)
    result = runner.run(config, manifest=manifest, evaluate=lambda arm, seed, repeat: {"score": seed + repeat, "arm": arm})
    export = runner.export(result, tmp_path / "export.json")
    assert verify_export(export)
    data = export.read_text(); export.write_text(data.replace('"score":2','"score":999'))
    assert not verify_export(export)


def test_guidance_budget_rejects_before_calling_model():
    from cypher.guidance.pipeline import BudgetExceeded

    project_id, target_id, requester, policy_id = uuid4(), uuid4(), uuid4(), uuid4()
    context = ValidationContext(True, frozenset({"getOrder"}), frozenset({"user_a", "user_b"}),
                                frozenset({"orders.a1"}), frozenset({policy_id}), frozenset({"orders.read.owner_only"}))
    client = FakeLLMClient([{"capsules": []}])
    service = GuidanceService(llm=client, validation_context=lambda *_: context, dry_run=lambda _aic: True,
                              token_cap=100, cost_cap_usd=1.0)
    with pytest.raises(BudgetExceeded):
        service.suggest_capsules(SuggestRequest(project_id, requester, target_id, ("getOrder",),
            {"operations": [{"operation_id": "getOrder", "method": "GET", "path": "/orders/{order_id}"}]}, 1))
    assert client.calls == []
