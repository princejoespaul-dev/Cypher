from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from cypher.capsules.canonical import capsule_content_hash, capsule_fingerprint
from cypher.capsules.models import AIC
from cypher.capsules.validators import ValidationContext, assert_minimal_mutation, validate_aic_layers_1_to_4
from cypher.capsules.versioning import CapsuleStatus, CapsuleStore
from cypher.core.canonical import canonical_json_bytes, sha256_hex


def context(policy_id):
    return ValidationContext(True, frozenset({"getOrder"}), frozenset({"user_a", "user_b"}),
                             frozenset({"orders.a1"}), frozenset({policy_id}), frozenset({"orders.read.owner_only"}))


def test_aic_schema_hash_and_fingerprint_are_stable(valid_aic):
    assert len(capsule_content_hash(valid_aic)) == 64
    assert len(capsule_fingerprint(valid_aic)) == 64
    renamed = valid_aic.model_copy(update={"title": "Different title"})
    assert capsule_fingerprint(renamed) == capsule_fingerprint(valid_aic)
    assert capsule_content_hash(renamed) != capsule_content_hash(valid_aic)


def test_aic_strict_unknown_field_rejected(valid_aic):
    raw = valid_aic.model_dump(mode="json", by_alias=True)
    raw["unexpected"] = "should fail"
    with pytest.raises(ValidationError):
        AIC.model_validate(raw)


def test_reference_and_safety_layers_pass(valid_aic, policy_id):
    model, issues = validate_aic_layers_1_to_4(valid_aic.model_dump(mode="json", by_alias=True), context(policy_id))
    assert model is not None
    assert issues == ()


def test_production_or_non_sandbox_aic_rejected(valid_aic, policy_id):
    raw = valid_aic.model_dump(mode="json", by_alias=True)
    raw["safety"]["sandbox_only"] = False
    model, issues = validate_aic_layers_1_to_4(raw, context(policy_id))
    assert model is not None
    assert any(issue.code == "env.not_sandbox" for issue in issues)


def test_secret_values_and_fields_rejected(valid_aic, policy_id):
    raw = valid_aic.model_dump(mode="json", by_alias=True)
    raw["positive_control"]["request"]["body"] = {"access_token": "abc"}
    _, issues = validate_aic_layers_1_to_4(raw, context(policy_id))
    assert any(issue.code == "aic.secret_field" for issue in issues)


def test_minimality_allows_one_declared_path_and_rejects_extra_change():
    before = {"principal": "user_a", "path": "/orders/order-a", "body": {"quantity": 1}}
    after = {"principal": "user_b", "path": "/orders/order-a", "body": {"quantity": 1}}
    assert_minimal_mutation(before, after, dimension="principal", allowed_path="$.principal")
    with pytest.raises(ValueError):
        assert_minimal_mutation(before, {**after, "body": {"quantity": 2}}, dimension="principal", allowed_path="$.principal")


def test_capsule_versions_are_immutable_and_status_events_append(valid_aic):
    store, project, actor = CapsuleStore(), uuid4(), uuid4()
    version = store.create(project, actor, valid_aic)
    assert store.status(version.capsule_version_id) == CapsuleStatus.DRAFT
    store.transition(version.capsule_version_id, project, actor, CapsuleStatus.VALIDATED)
    store.transition(version.capsule_version_id, project, actor, CapsuleStatus.APPROVED)
    assert store.status(version.capsule_version_id) == CapsuleStatus.APPROVED
    with pytest.raises(ValueError):
        store.transition(version.capsule_version_id, project, actor, CapsuleStatus.DRAFT)


def test_canonical_json_number_and_unicode_ordering():
    assert canonical_json_bytes({"b": 1.0, "a": -0.0}) == b'{"a":0,"b":1}'
    assert canonical_json_bytes(1e-6) == b"0.000001"
    assert canonical_json_bytes(1e-7) == b"1e-7"
    assert sha256_hex(canonical_json_bytes({"x": "é"})) == sha256_hex(canonical_json_bytes({"x": "é"}))
