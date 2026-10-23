from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from cypher.api.app import DEV_PROJECT_ID, DEV_USER_ID, create_app
from cypher.core.auth import ApiKeyRegistry, Role
from cypher.capsules.versioning import CapsuleStatus

DEV_HEADERS = {"Authorization": "Bearer dev-only-change-me"}


def test_generated_openapi_includes_phase_routes():
    schema = create_app().openapi()
    paths = schema["paths"]
    assert "/v1/replays" in paths
    assert "/v1/replays/{run_id}/evidence" in paths
    assert "/v1/suggestions" in paths
    assert "/v1/audit" in paths
    assert "/v1/experiments/{experiment_id}/results" in paths


def test_audit_api_verifies_chain_and_requires_authentication():
    client = TestClient(create_app())
    assert client.get("/v1/audit").status_code == 401
    created = client.post("/v1/targets", headers=DEV_HEADERS, json={
        "name": "audit-target", "base_url": "http://orders.test:8000", "host_allowlist": ["orders.test"]
    })
    assert created.status_code == 201, created.text
    audit = client.get("/v1/audit?verify_chain=true", headers=DEV_HEADERS)
    assert audit.status_code == 200, audit.text
    assert audit.json()["chain_valid"] is True
    assert any(row["action"] == "target.created" for row in audit.json()["items"])


def test_project_scoping_hides_another_projects_target():
    registry = ApiKeyRegistry()
    project_a, project_b = uuid4(), uuid4()
    user_a, user_b = uuid4(), uuid4()
    registry.register("project-a-key-very-long", user_id=user_a, project_id=project_a, role=Role.ADMIN)
    registry.register("project-b-key-very-long", user_id=user_b, project_id=project_b, role=Role.ADMIN)
    client = TestClient(create_app(api_keys=registry))
    target = client.post("/v1/targets", headers={"Authorization": "Bearer project-a-key-very-long"}, json={
        "name": "private-target", "base_url": "http://orders.test:8000", "host_allowlist": ["orders.test"]
    })
    assert target.status_code == 201, target.text
    target_id = target.json()["target_id"]
    hidden = client.get(f"/v1/targets/{target_id}", headers={"Authorization": "Bearer project-b-key-very-long"})
    assert hidden.status_code == 404


def test_direct_ai_authored_capsule_cannot_bypass_suggestion_approval(valid_aic):
    client = TestClient(create_app())
    target = client.post("/v1/targets", headers=DEV_HEADERS, json={
        "name": "ai-bypass-target", "base_url": "http://orders.test:8000", "host_allowlist": ["orders.test"]
    })
    assert target.status_code == 201
    payload = valid_aic.model_dump(mode="json", by_alias=True)
    payload["provenance"] = {"authored_by": "guidance", "suggestion_id": str(uuid4())}
    response = client.post("/v1/capsules", headers=DEV_HEADERS, json={"target_id": target.json()["target_id"], "content": payload})
    assert response.status_code == 403
    assert response.json()["code"] == "capsule.ai_approval_bypass"


def test_replay_submission_requires_idempotency_key_before_dispatch():
    client = TestClient(create_app())
    response = client.post("/v1/replays", headers=DEV_HEADERS, json={
        "capsule_version_id": str(uuid4()), "build_ids": [str(uuid4())], "repeats": 3
    })
    assert response.status_code == 400
    assert response.json()["code"] == "idempotency.required"


def test_replay_route_fails_closed_when_worker_is_unconfigured(valid_aic):
    client = TestClient(create_app())
    created_target = client.post("/v1/targets", headers=DEV_HEADERS, json={
        "name": "replay-target", "base_url": "http://orders.test:8000", "host_allowlist": ["orders.test"]
    })
    assert created_target.status_code == 201
    target_id = created_target.json()["target_id"]
    spec = {"openapi": "3.1.0", "info": {"title": "fixture", "version": "1"}, "paths": {
        "/orders/{order_id}": {"get": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}}
    }}
    assert client.post(f"/v1/targets/{target_id}/openapi", headers=DEV_HEADERS, json={"document": spec}).status_code == 201
    build = client.post(f"/v1/targets/{target_id}/builds", headers=DEV_HEADERS, json={
        "label": "vulnerable", "git_ref": "test-commit", "image_digest": "sha256:" + "a" * 64
    })
    assert build.status_code == 201, build.text
    # Seed an approved capsule directly for this safety test; the public approval route correctly
    # refuses approval until a real dry-run worker has been configured.
    content = valid_aic.model_copy(update={"state_oracle": valid_aic.state_oracle.model_copy(update={"enabled": False})})
    created = client.app.state.capsules.create(DEV_PROJECT_ID, DEV_USER_ID, content)
    client.app.state.capsules.transition(created.capsule_version_id, DEV_PROJECT_ID, DEV_USER_ID, CapsuleStatus.VALIDATED)
    client.app.state.capsules.transition(created.capsule_version_id, DEV_PROJECT_ID, DEV_USER_ID, CapsuleStatus.APPROVED)
    response = client.post("/v1/replays", headers={**DEV_HEADERS, "Idempotency-Key": "replay-test-1"}, json={
        "capsule_version_id": str(created.capsule_version_id), "build_ids": [build.json()["build_id"]], "repeats": 1
    })
    assert response.status_code == 503
    assert response.json()["code"] == "worker.not_configured"


def test_environment_creation_fails_closed_without_factory():
    client = TestClient(create_app())
    target = client.post("/v1/targets", headers=DEV_HEADERS, json={
        "name": "no-factory", "base_url": "http://orders.test:8000", "host_allowlist": ["orders.test"]
    })
    assert target.status_code == 201
    build = client.post(f"/v1/targets/{target.json()['target_id']}/builds", headers=DEV_HEADERS, json={
        "label": "vulnerable", "git_ref": "test-commit", "image_digest": "sha256:" + "c" * 64
    })
    assert build.status_code == 201
    response = client.post(f"/v1/builds/{build.json()['build_id']}/environments", headers=DEV_HEADERS)
    assert response.status_code == 503
    assert response.json()["code"] == "sandbox.not_configured"
