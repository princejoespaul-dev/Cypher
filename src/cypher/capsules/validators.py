"""Layered AIC validators for references, minimality and sandbox safety."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import ValidationError as PydanticValidationError

from cypher.capsules.models import AIC

SECRET_KEY = re.compile(r"(?i)(authorization|cookie|set-cookie|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)")
TOKEN_VALUE = re.compile(r"(?i)\b(bearer\s+[a-z0-9._~+/-]+=*|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b")


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    layer: int
    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationContext:
    sandbox_only: bool
    operation_ids: frozenset[str]
    principal_names: frozenset[str]
    fixture_refs: frozenset[str]
    policy_version_ids: frozenset[UUID]
    policy_rule_ids: frozenset[str]
    destructive_methods: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    max_body_bytes: int = 1_048_576
    operation_specs: dict[str, dict[str, str]] | None = None
    oracle_probe_names: frozenset[str] | None = None


def _find_secret(value: Any, path: str = "$") -> list[ValidationIssue]:
    found: list[ValidationIssue] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if SECRET_KEY.search(str(key)):
                found.append(ValidationIssue(2, "aic.secret_field", "Secret-bearing field names are forbidden in capsules", f"{path}.{key}"))
            found.extend(_find_secret(nested, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            found.extend(_find_secret(nested, f"{path}[{index}]"))
    elif isinstance(value, str) and TOKEN_VALUE.search(value):
        found.append(ValidationIssue(2, "aic.secret_value", "Token-like values are forbidden in capsules", path))
    return found


def validate_aic_layers_1_to_4(raw: dict[str, Any], context: ValidationContext) -> tuple[AIC | None, tuple[ValidationIssue, ...]]:
    """Return a strict model plus machine-readable errors; layer 5 is a dry run."""
    issues: list[ValidationIssue] = []
    try:
        aic = AIC.model_validate(raw)
    except PydanticValidationError as exc:
        for error in exc.errors(include_input=False):
            issues.append(ValidationIssue(1, "aic.schema_invalid", str(error.get("msg", "Schema error")), ".".join(map(str, error.get("loc", ())))))
        return None, tuple(issues)

    dumped = aic.model_dump(mode="json", by_alias=True)
    issues.extend(_find_secret(dumped))
    if aic.target.operation_id not in context.operation_ids:
        issues.append(ValidationIssue(2, "aic.operation_unknown", "Operation is not present in the registered OpenAPI document", "target.operation_id"))
    elif context.operation_specs is not None:
        registered = context.operation_specs.get(aic.target.operation_id)
        if registered is None or registered.get("method") != aic.target.method or registered.get("path") != aic.target.path:
            issues.append(ValidationIssue(2, "aic.operation_mismatch", "Method and path must exactly match the registered OpenAPI operation", "target"))
    if aic.principals.owner not in context.principal_names or aic.principals.other not in context.principal_names:
        issues.append(ValidationIssue(2, "aic.principal_unknown", "Both principals must be registered on the target", "principals"))
    if aic.resource.fixture_ref not in context.fixture_refs:
        issues.append(ValidationIssue(2, "aic.fixture_unknown", "Fixture reference does not exist on the target", "resource.fixture_ref"))
    if aic.policy.policy_version_id not in context.policy_version_ids or aic.policy.rule_id not in context.policy_rule_ids:
        issues.append(ValidationIssue(2, "aic.policy_unknown", "Policy version or rule id is not registered", "policy"))

    mutation = aic.counterfactual.mutation
    if mutation.dimension == "object_id" and not ("{" in aic.target.path and "}" in aic.target.path):
        issues.append(ValidationIssue(3, "aic.object_id_not_in_path", "object_id mutation requires an identifier path parameter", "target.path"))
    # The counterfactual stores only one mutation operation; additional overrides are not representable.
    if mutation.dimension not in {"principal", "object_id"}:
        issues.append(ValidationIssue(3, "aic.mutation_not_minimal", "Mutation dimension is outside the v1 allowlist", "counterfactual.mutation.dimension"))

    if not aic.safety.sandbox_only or not context.sandbox_only:
        issues.append(ValidationIssue(4, "env.not_sandbox", "AIC validation requires a target explicitly marked sandbox-only", "safety.sandbox_only"))
    if aic.target.method in context.destructive_methods and not aic.safety.destructive:
        issues.append(ValidationIssue(4, "aic.destructive_not_declared", "Non-safe HTTP methods require destructive=true", "safety.destructive"))
    try:
        import json
        body_len = len(json.dumps(dumped, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        body_len = context.max_body_bytes + 1
    if body_len > context.max_body_bytes:
        issues.append(ValidationIssue(4, "aic.body_too_large", "Capsule exceeds the configured JSON size limit"))
    if aic.state_oracle.enabled and not aic.safety.sandbox_only:
        issues.append(ValidationIssue(4, "oracle.not_sandbox", "State oracle is permitted only for sandbox targets", "state_oracle"))
    if aic.state_oracle.enabled and context.oracle_probe_names is not None:
        unknown_probes = set(aic.state_oracle.probes) - set(context.oracle_probe_names)
        if unknown_probes:
            issues.append(ValidationIssue(2, "oracle.probe_unknown", "State-oracle probe is not registered on this target", "state_oracle.probes"))
    return aic, tuple(issues)


def assert_minimal_mutation(before: dict[str, Any], after: dict[str, Any], *, dimension: str, allowed_path: str) -> None:
    """Strict structural diff guard used by renderers/tests for concrete request pairs."""
    if dimension not in {"principal", "object_id"}:
        raise ValueError("unsupported mutation dimension")
    diffs: list[str] = []

    def walk(left: Any, right: Any, path: str = "$") -> None:
        if type(left) is not type(right):
            diffs.append(path)
        elif isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    diffs.append(f"{path}.{key}")
                else:
                    walk(left[key], right[key], f"{path}.{key}")
        elif isinstance(left, list):
            if len(left) != len(right):
                diffs.append(path)
            else:
                for index, (a, b) in enumerate(zip(left, right, strict=True)):
                    walk(a, b, f"{path}[{index}]")
        elif left != right:
            diffs.append(path)

    walk(before, after)
    normalized_allowed = allowed_path.rstrip(".")
    if not diffs or any(path != normalized_allowed and not path.startswith(normalized_allowed + ".") and not path.startswith(normalized_allowed + "[") for path in diffs):
        raise ValueError(f"Counterfactual must change only {normalized_allowed}; found structural changes at {diffs}")
