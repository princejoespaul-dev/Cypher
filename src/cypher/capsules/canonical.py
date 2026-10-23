"""AIC canonicalization, content hashing and recurrence fingerprints."""
from __future__ import annotations

from typing import Any

from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.capsules.models import AIC


def canonical_aic(aic: AIC | dict[str, Any]) -> bytes:
    value = aic.model_dump(mode="json", by_alias=True, exclude_none=False) if isinstance(aic, AIC) else aic
    return canonical_json_bytes(value)


def capsule_content_hash(aic: AIC | dict[str, Any]) -> str:
    return sha256_hex(canonical_aic(aic))


def capsule_fingerprint(aic: AIC) -> str:
    """Stable recurrence key intentionally independent of title/version/content hash."""
    source = {
        "operation_template": {"operation_id": aic.target.operation_id, "method": aic.target.method, "path": aic.target.path},
        "mutation_dimension": aic.counterfactual.mutation.dimension,
        "policy_rule_id": aic.policy.rule_id,
        "resource_type": aic.resource.type,
    }
    return sha256_hex(canonical_json_bytes(source))
