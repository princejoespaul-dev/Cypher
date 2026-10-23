"""Deterministic replay orchestration over injected sandbox, login, oracle and evidence ports."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID, uuid4

from cypher.capsules.models import AIC
from cypher.core.canonical import canonical_json_bytes
from cypher.evidence.store import EvidenceStore
from cypher.harness.adjudicator.rules import adjudicate
from cypher.harness.executor import HttpObservation, SafeHttpExecutor
from cypher.harness.renderer import render_request
from cypher.harness.phase5_models import EvidenceBundle, Verdict


class EnvironmentPort(Protocol):
    def get_base_url(self, environment_id: UUID) -> str: ...
    def is_sandbox(self, environment_id: UUID) -> bool: ...
    def reset_to_seed(self, environment_id: UUID, seed: int) -> str: ...


class PrincipalAuthenticator(Protocol):
    def token_for(self, *, environment_id: UUID, principal_name: str) -> str: ...


class StateOraclePort(Protocol):
    def prove_read_only(self, *, environment_id: UUID, project_id: UUID) -> None: ...
    def probe_hashes(self, *, environment_id: UUID, project_id: UUID, probe_names: tuple[str, ...]) -> dict[str, str]: ...


@dataclass(frozen=True, slots=True)
class ReplayResult:
    run_id: UUID
    verdict: Verdict
    fired_rules: tuple[str, ...]
    signals: dict[str, bool | None]
    completeness_score: float
    evidence_hash: str
    repeat_verdicts: tuple[str, ...]


class ReplayEngine:
    """One capsule/build replay, resetting seed before each repeat and recording redacted evidence."""
    def __init__(self, *, environments: EnvironmentPort, auth: PrincipalAuthenticator, oracle: StateOraclePort,
                 executor: SafeHttpExecutor, evidence_store: EvidenceStore, harness_version: str = "1.0.0") -> None:
        self._env = environments
        self._auth = auth
        self._oracle = oracle
        self._executor = executor
        self._evidence = evidence_store
        self._harness_version = harness_version

    def replay(self, *, project_id: UUID, environment_id: UUID, target_allowlist: tuple[str, ...],
               aic: AIC, capsule_hash: str, build_image_digest: str, seed: int, repeats: int = 3,
               ownership_map: dict[str, dict[str, Any]] | None = None) -> ReplayResult:
        if not self._env.is_sandbox(environment_id):
            raise ValueError("env.not_sandbox: replay cannot start outside a sandbox environment")
        if repeats < 1 or repeats > 5:
            raise ValueError("repeats must be between 1 and 5")
        # Scope/DNS preflight happens before any sandbox reset or request. The executor repeats
        # the same checks and pins the socket to a validated address immediately before send.
        base_url = self._env.get_base_url(environment_id)
        self._executor.preflight(base_url=base_url, allowlist=target_allowlist, sandbox_only=True)
        verdicts: list[tuple[Verdict, tuple[str, ...], dict[str, bool | None], float, str]] = []
        final_evidence_hash = ""
        if aic.state_oracle.enabled:
            prove = getattr(self._oracle, "prove_read_only", None)
            if not callable(prove):
                raise RuntimeError("oracle.read_only_unproven: state oracle does not implement the read-only proof")
            prove(environment_id=environment_id, project_id=project_id)
        for index in range(repeats):
            seed_hash = self._env.reset_to_seed(environment_id, seed)
            base_url = self._env.get_base_url(environment_id)
            fixture_map = ownership_map or {}
            owner_request = render_request(aic, principal_name=aic.principals.owner, fixture_map=fixture_map)
            owner_token = self._auth.token_for(environment_id=environment_id, principal_name=aic.principals.owner)
            positive = self._executor.send(base_url=base_url, allowlist=target_allowlist, sandbox_only=True, request=owner_request, bearer_token=owner_token, step="positive_control")
            counter_request = render_request(aic, principal_name=aic.principals.other, fixture_map=fixture_map, counterfactual=True)
            if aic.safety.destructive:
                # The positive control may mutate state. Restore a seed before the destructive counterfactual,
                # then restore again after it so a failed run cannot poison the shared sandbox.
                self._env.reset_to_seed(environment_id, seed)
            pre = self._oracle.probe_hashes(environment_id=environment_id, project_id=project_id, probe_names=tuple(aic.state_oracle.probes)) if aic.state_oracle.enabled else {}
            counter_token = self._auth.token_for(environment_id=environment_id, principal_name=counter_request.principal_name)
            counter = self._executor.send(base_url=base_url, allowlist=target_allowlist, sandbox_only=True, request=counter_request, bearer_token=counter_token, step="counterfactual")
            post = self._oracle.probe_hashes(environment_id=environment_id, project_id=project_id, probe_names=tuple(aic.state_oracle.probes)) if aic.state_oracle.enabled else {}
            if aic.safety.destructive:
                self._env.reset_to_seed(environment_id, seed)
            observations = (self._observation_dict(positive), self._observation_dict(counter))
            snapshots = tuple([{"phase": "pre", "probe_name": name, "result_sha256": digest} for name, digest in sorted(pre.items())] +
                              [{"phase": "post", "probe_name": name, "result_sha256": digest} for name, digest in sorted(post.items())])
            evidence_capsule = aic.model_dump(mode="json", by_alias=True)
            evidence_capsule.update({"content_hash": capsule_hash, "build_image_digest": build_image_digest,
                                     "seed_snapshot_hash": seed_hash, "harness_version": self._harness_version,
                                     "adjudicator_version": "1.0.0", "redaction_report": {"stored_redacted_only": True}})
            bundle = EvidenceBundle(capsule=evidence_capsule, observations=observations, state_snapshots=snapshots, config={})
            decision = adjudicate(bundle, adjudicator_version="1.0.0")
            # Only pre/post hashes are persisted in records; full state query results go to the evidence store.
            evidence_blob = {"capsule": evidence_capsule, "observations": observations, "state_snapshots": snapshots, "config": {}}
            final_evidence_hash = self._evidence.put_bytes(project_id=project_id, data=canonical_json_bytes(evidence_blob, permit_float=True), content_type="application/json")
            verdicts.append((decision.verdict, decision.fired_rules, decision.signals, decision.completeness_score, final_evidence_hash))
        observed = {item[0] for item in verdicts}
        if len(observed) > 1:
            return ReplayResult(uuid4(), Verdict.INCONCLUSIVE_FLAKY, ("R7_REPEAT_DISAGREEMENT",),
                                {"repeat_disagreement": True}, min(v[3] for v in verdicts), final_evidence_hash,
                                tuple(v[0].value for v in verdicts))
        last = verdicts[-1]
        return ReplayResult(uuid4(), last[0], last[1], last[2], min(v[3] for v in verdicts), final_evidence_hash,
                            tuple(v[0].value for v in verdicts))

    @staticmethod
    def _observation_dict(observation: HttpObservation) -> dict[str, Any]:
        return {"step": observation.step, "request": observation.request, "status_code": observation.status_code,
                "response_headers": observation.response_headers, "body_json": observation.body_json,
                "body_text": observation.body_text, "response_sha256": observation.response_sha256,
                "latency_ms": observation.latency_ms, "error": observation.error,
                "redaction_report": observation.redaction_report}
