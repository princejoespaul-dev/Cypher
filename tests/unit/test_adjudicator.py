from __future__ import annotations

from cypher.harness.adjudicator.rules import adjudicate
from cypher.harness.phase5_models import EvidenceBundle, Verdict


def bundle(*, positive_status=200, cf_status=403, owner_body=None, cf_body=None, env_error=False,
           pre_hash="a"*64, post_hash="a"*64, state_oracle=True):
    capsule = {"positive_control": {"expect": {"status_in": [200], "fingerprint_fields": ["$.customer_email"]}},
               "counterfactual": {"expect_denied": {"status_in": [401,403,404]}},
               "state_oracle": {"enabled": state_oracle, "probes": ["orders_hash"]},
               "policy": {"rule_id": "orders.owner"}, "content_hash": "c"*64,
               "build_image_digest": "sha256:"+"d"*64, "seed_snapshot_hash": "e"*64,
               "harness_version": "1.0", "adjudicator_version": "1.0", "redaction_report": {"safe": True}}
    observations = (
        {"step": "positive_control", "status_code": positive_status, "body_json": owner_body or {"id":"order-a", "customer_email":"a@example.test"}, "response_sha256": "1"*64, "request": {"method":"GET"}},
        {"step": "counterfactual", "status_code": cf_status, "body_json": cf_body or {"error":"forbidden"}, "response_sha256": "2"*64, "request": {"method":"GET"}, "error": "network" if env_error else None},
    )
    snapshots = ({"phase":"pre","probe_name":"orders_hash","result_sha256":pre_hash}, {"phase":"post","probe_name":"orders_hash","result_sha256":post_hash}) if state_oracle else ()
    return EvidenceBundle(capsule=capsule, observations=observations, state_snapshots=snapshots, config={})


def test_adjudicator_rules_in_order():
    assert adjudicate(bundle(env_error=True, pre_hash="a"*64, post_hash="b"*64)).verdict == Verdict.INCONCLUSIVE_ENVIRONMENT
    assert adjudicate(bundle(positive_status=403)).verdict == Verdict.INCONCLUSIVE_CONTROL
    assert adjudicate(bundle(cf_status=403, pre_hash="a"*64, post_hash="b"*64)).verdict == Verdict.VULNERABLE_STATE_CHANGE
    assert adjudicate(bundle(state_oracle=False, cf_status=200, cf_body={"customer_email":"a@example.test"})).verdict == Verdict.VULNERABLE_DATA_EXPOSURE
    assert adjudicate(bundle(state_oracle=False, cf_status=404)).verdict == Verdict.PROTECTED
    assert adjudicate(bundle(state_oracle=False, cf_status=200, cf_body={"ok":True})).verdict == Verdict.INCONCLUSIVE_AMBIGUOUS


def test_adjudicator_bytes_are_deterministic_for_100_runs():
    evidence = bundle(cf_status=403, pre_hash="a"*64, post_hash="b"*64)
    outputs = [adjudicate(evidence).model_dump_json() for _ in range(100)]
    assert len(set(outputs)) == 1
