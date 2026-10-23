from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from cypher.api.app import create_app
from cypher.core.audit import HashChainedAuditLog
from cypher.harness.renderer import render_request


def test_renderer_changes_only_principal_or_object_id(valid_aic):
    fixtures = {"user_a":{"order":{"orders.a1":"order-a1"}}, "user_b":{"order":{"orders.a1":"order-b1"}}}
    owner = render_request(valid_aic, principal_name="user_a", fixture_map=fixtures)
    counter = render_request(valid_aic, principal_name="user_b", fixture_map=fixtures, counterfactual=True)
    assert owner.path == counter.path == "/orders/order-a1"
    assert owner.principal_name == "user_a" and counter.principal_name == "user_b"
    raw = valid_aic.model_dump(mode="json", by_alias=True)
    raw["counterfactual"]["mutation"] = {"dimension":"object_id","from":"$resource.id","to":"$resource.other_id"}
    from cypher.capsules.models import AIC
    object_aic = AIC.model_validate(raw)
    obj_counter = render_request(object_aic, principal_name="user_a", fixture_map=fixtures, counterfactual=True)
    assert obj_counter.principal_name == "user_a" and obj_counter.path == "/orders/order-b1"


def test_audit_chain_detects_tampering():
    log = HashChainedAuditLog(); project, actor = uuid4(), uuid4()
    first = log.append(actor_id=actor, project_id=project, action="a", object_ref="x", payload={"ok": True})
    log.append(actor_id=actor, project_id=project, action="b", object_ref="y", payload={"ok": False})
    assert log.verify(project)
    log._entries[0] = type(first)(first.seq, first.actor_id, first.project_id, first.action, first.object_ref,
        first.payload_sha256, first.prev_hash, "0"*64, first.created_at)
    assert not log.verify(project)


def test_api_auth_and_health_and_target_scope():
    client = TestClient(create_app())
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/targets").status_code == 401
    headers = {"Authorization":"Bearer dev-only-change-me"}
    response = client.post("/v1/targets", headers=headers, json={"name":"ref","base_url":"http://orders.test:8000",
        "host_allowlist":["orders.test"],"openapi_spec_ref":"inline"})
    assert response.status_code == 201, response.text
    target_id = response.json()["target_id"]
    openapi = {"openapi":"3.1.0","info":{"title":"reference","version":"1"},"paths":{"/orders/{order_id}":{"get":{"operationId":"getOrder","responses":{"200":{"description":"ok"}}}}}}
    response = client.post(f"/v1/targets/{target_id}/openapi", headers=headers, json={"document":openapi})
    assert response.status_code == 201
    response = client.post(f"/v1/targets/{target_id}/fixtures", headers=headers, json={"fixture_refs":["orders.a1"]})
    assert response.status_code == 201
    response = client.post(f"/v1/targets/{target_id}/principals", headers=headers, json={"name":"user_a","role":"owner","credential_ref":"secret://users/a","login_flow":{"kind":"bearer_fixture"}})
    assert response.status_code == 201, response.text
    response = client.post(f"/v1/targets/{target_id}/principals", headers=headers, json={"name":"user_b","role":"user","credential_ref":"secret://users/b","login_flow":{"kind":"bearer_fixture"}})
    assert response.status_code == 201, response.text
    policy = client.post(f"/v1/targets/{target_id}/policies", headers=headers, json={"rules":[{"rule_id":"orders.read.owner_only","resource_type":"order","action":"read","allow_when":"principal.id == resource.owner_id"}]})
    assert policy.status_code == 201, policy.text
    pid = policy.json()["policy_version_id"]
    probe = client.post(f"/v1/targets/{target_id}/oracle-probes", headers=headers,
        json={"name":"orders_row_hash", "sql":"SELECT id, owner_id FROM orders ORDER BY id"})
    assert probe.status_code == 201, probe.text
    capsule = {"target_id":target_id,"content":{"aic_version":"1.0","title":"owner only","vuln_class":"BOLA",
       "target":{"operation_id":"getOrder","method":"GET","path":"/orders/{order_id}"},
       "policy":{"policy_version_id":pid,"rule_id":"orders.read.owner_only"},
       "principals":{"owner":"user_a","other":"user_b"},"resource":{"type":"order","fixture_ref":"orders.a1"},
       "positive_control":{"as":"user_a","request":{"path_params":{"order_id":"$resource.id"}},"expect":{"status_in":[200],"fingerprint_fields":["$.customer_email"]}},
       "counterfactual":{"mutation":{"dimension":"principal","from":"user_a","to":"user_b"},"expect_denied":{"status_in":[401,403,404],"leak_check":"fingerprint_absent"}},
       "state_oracle":{"enabled":True,"probes":["orders_row_hash"],"expect":"unchanged"},"safety":{"sandbox_only":True,"destructive":False},
       "provenance":{"authored_by":"human","suggestion_id":None}}}
    created = client.post("/v1/capsules", headers=headers, json=capsule)
    assert created.status_code == 201, created.text
    version_id = created.json()["capsule_version_id"]
    validated = client.post(f"/v1/capsules/{version_id}/validate", headers=headers)
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True
    # Approval remains blocked until the real sandbox dry-run worker is configured.
    approved = client.post(f"/v1/capsules/{version_id}/approve", headers=headers)
    assert approved.status_code == 409
