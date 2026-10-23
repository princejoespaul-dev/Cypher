from __future__ import annotations

import tempfile
from uuid import uuid4

import pytest

from cypher.evidence.redaction import redact_value, redact_json_text
from cypher.evidence.store import FileEvidenceStore
from cypher.sandbox.allowlist import ScopeViolation, validate_destination
from cypher.sandbox.oracle import UnsafeProbe, validate_select_probe


def test_allowlist_requires_exact_host_and_sandbox_address():
    resolved = lambda host, port: ["172.28.0.15"]
    value = validate_destination("http://orders.test:8000/orders/a", host_allowlist=("orders.test",),
                                 sandbox_only=True, sandbox_subnets=("172.28.0.0/16",), resolver=resolved)
    assert value.hostname == "orders.test"
    with pytest.raises(ScopeViolation, match="host_not_allowed"):
        validate_destination("http://evil.test/", host_allowlist=("orders.test",), sandbox_only=True,
                             sandbox_subnets=("172.28.0.0/16",), resolver=resolved)
    with pytest.raises(ScopeViolation, match="address_not_sandbox"):
        validate_destination("http://orders.test/", host_allowlist=("orders.test",), sandbox_only=True,
                             sandbox_subnets=("172.28.0.0/16",), resolver=lambda *_: ["8.8.8.8"])
    with pytest.raises(ScopeViolation, match="ip_literal_denied"):
        validate_destination("http://172.28.0.5/", host_allowlist=("172.28.0.5",), sandbox_only=True,
                             sandbox_subnets=("172.28.0.0/16",), resolver=resolved)
    with pytest.raises(ScopeViolation, match="not_sandbox"):
        validate_destination("http://orders.test/", host_allowlist=("orders.test",), sandbox_only=False,
                             sandbox_subnets=("172.28.0.0/16",), resolver=resolved)


def test_probe_validator_rejects_non_select_and_sql_injection():
    assert validate_select_probe(" SELECT id FROM orders WHERE id = :order_id; ") == "SELECT id FROM orders WHERE id = :order_id"
    for value in ["UPDATE orders SET amount=0", "SELECT * FROM orders; DROP TABLE users", "SELECT * FROM orders -- comment", "WITH x AS (SELECT 1) SELECT * FROM x", "SELECT * INTO danger FROM orders"]:
        with pytest.raises(UnsafeProbe):
            validate_select_probe(value)


def test_redaction_covers_nested_sensitive_fields_and_tokens():
    raw = {"headers": {"Authorization": "Bearer topsecret"}, "nested": {"access_token": "secret-value"}, "text": "eyJabcdefghijk.abcdefghijk.abcdefghijk"}
    safe, report = redact_value(raw)
    dumped = str(safe)
    assert "topsecret" not in dumped and "secret-value" not in dumped and "eyJabcdefghijk" not in dumped
    assert report.fields_redacted == 2
    safe_text, _ = redact_json_text('{"password":"hunter2","note":"Bearer tokentokentoken"}')
    assert "hunter2" not in safe_text and "tokentokentoken" not in safe_text


def test_evidence_store_is_content_addressed_scoped_and_integrity_checked(tmp_path):
    store = FileEvidenceStore(tmp_path)
    project_a, project_b = uuid4(), uuid4()
    digest = store.put_bytes(project_id=project_a, data=b"redacted evidence", content_type="text/plain")
    assert store.read_bytes(project_id=project_a, content_sha256=digest) == b"redacted evidence"
    assert store.read_bytes(project_id=project_b, content_sha256=digest) is None
    assert len(digest) == 64


def test_environment_manager_allocates_unique_subnets_and_rejects_wrong_seed_hash():
    from types import SimpleNamespace

    from cypher.sandbox.environment import DockerEnvironmentManager, EnvironmentStatus

    class FakeNetwork:
        def __init__(self, name: str, subnet: str) -> None:
            self.id = f"network-{name}"
            self.name = name
            self.subnet = subnet

        def remove(self) -> None:
            return None

    class FakeContainer:
        def __init__(self, name: str) -> None:
            self.id = f"container-{name}"
            self.name = name

        def reload(self) -> None:
            return None

        def remove(self, **_kwargs) -> None:
            return None

    class FakeNetworks:
        def __init__(self) -> None:
            self.by_id = {}
            self.created = []

        def create(self, *, name: str, ipam: dict, **_kwargs):
            subnet = ipam["Config"][0]["Subnet"]
            obj = FakeNetwork(name, subnet)
            self.by_id[obj.id] = obj
            self.created.append(obj)
            return obj

        def get(self, network_id: str):
            return self.by_id[network_id]

    class FakeContainers:
        def __init__(self) -> None:
            self.by_id = {}

        def run(self, *, network: str, **_kwargs):
            obj = FakeContainer(network)
            self.by_id[obj.id] = obj
            return obj

        def get(self, container_id: str):
            return self.by_id[container_id]

    networks, containers = FakeNetworks(), FakeContainers()
    docker = SimpleNamespace(networks=networks, containers=containers,
                             images=SimpleNamespace(get=lambda digest: digest))
    expected_seed = "a" * 64
    reset_hash = {"value": expected_seed}
    manager = DockerEnvironmentManager(docker_client=docker, health_check=lambda _url: True,
                                       reset_runner=lambda _env, _seed: reset_hash["value"])
    first = manager.create(environment_id=uuid4(), project_id=uuid4(), build_id=uuid4(),
                           image_digest="sha256:" + "1" * 64, container_port=8000,
                           seed=lambda _container: {"seed_snapshot_hash": expected_seed, "ownership_map": {"user_a": {}}})
    second = manager.create(environment_id=uuid4(), project_id=first.project_id, build_id=uuid4(),
                            image_digest="sha256:" + "2" * 64, container_port=8000,
                            seed=lambda _container: {"seed_snapshot_hash": expected_seed, "ownership_map": {"user_a": {}}})
    assert first.network_subnet != second.network_subnet
    assert manager.get_environment(first.environment_id, uuid4()) is None
    assert manager.get_environment(first.environment_id, first.project_id).status == EnvironmentStatus.READY
    reset_hash["value"] = "b" * 64
    with pytest.raises(RuntimeError, match="sandbox.reset_mismatch"):
        manager.reset_to_seed(first.environment_id, 11)
    assert manager.get_environment(first.environment_id, first.project_id).status == EnvironmentStatus.FAILED


def test_http_executor_pins_dns_to_validated_sandbox_address_and_preserves_host_header():
    import httpx

    from cypher.harness.executor import SafeHttpExecutor
    from cypher.harness.renderer import RenderedRequest

    seen = []

    def response_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "order-a1", "owner_id": "user_a"})

    client = httpx.Client(transport=httpx.MockTransport(response_handler), follow_redirects=False, trust_env=False)
    resolved = []

    def resolver(host: str, port: int):
        resolved.append((host, port))
        return ["172.28.0.15"]

    executor = SafeHttpExecutor(client=client, resolver=resolver, sandbox_subnets=("172.28.0.0/16",))
    observation = executor.send(base_url="http://orders.test:8000", allowlist=("orders.test",), sandbox_only=True,
                                request=RenderedRequest("user_a", "GET", "/orders/order-a1", {"view": "safe"}, None),
                                bearer_token="fixture-token", step="positive_control")
    assert observation.status_code == 200
    assert len(seen) == 1 and len(resolved) == 1
    assert seen[0].url.host == "172.28.0.15"
    assert seen[0].headers["host"] == "orders.test:8000"
    assert "fixture-token" not in str(observation.request)
    client.close()


def test_http_executor_refuses_redirect_without_following_it():
    import httpx

    from cypher.harness.executor import SafeHttpExecutor
    from cypher.harness.renderer import RenderedRequest

    calls = []
    def response_handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        return httpx.Response(302, headers={"Location": "http://evil.test/steal"})

    client = httpx.Client(transport=httpx.MockTransport(response_handler), follow_redirects=True, trust_env=False)
    executor = SafeHttpExecutor(client=client, resolver=lambda *_: ["172.28.0.15"], sandbox_subnets=("172.28.0.0/16",))
    observation = executor.send(base_url="http://orders.test:8000", allowlist=("orders.test",), sandbox_only=True,
                                request=RenderedRequest("user_a", "GET", "/orders/order-a1", {}, None),
                                bearer_token=None, step="counterfactual")
    assert observation.error == "redirect_refused"
    assert calls == ["172.28.0.15"]
    client.close()
