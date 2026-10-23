"""Counterfactual rendering from the positive request; credentials resolve at replay time."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cypher.capsules.models import AIC
from cypher.capsules.validators import assert_minimal_mutation


@dataclass(frozen=True, slots=True)
class RenderedRequest:
    principal_name: str
    method: str
    path: str
    query_params: dict[str, Any]
    body: dict[str, Any] | list[Any] | None


def render_request(aic: AIC, *, principal_name: str, fixture_map: dict[str, dict[str, Any]], counterfactual: bool = False) -> RenderedRequest:
    """Render exactly one declared mutation; no secrets are allowed in the AIC itself.

    ``fixture_map`` has ``principal -> resource_type -> fixture_ref -> object_id`` shape.
    ``$resource.id`` resolves to the capsule resource owned by the declared owner.
    ``$resource.other_id`` resolves to the corresponding fixture owned by the other principal.
    """
    params = dict(aic.positive_control.request.path_params)
    query = dict(aic.positive_control.request.query_params)
    body = aic.positive_control.request.body
    owner_map = fixture_map.get(aic.principals.owner, {})
    other_map = fixture_map.get(aic.principals.other, {})
    owner_resources = owner_map.get(aic.resource.type, {})
    other_resources = other_map.get(aic.resource.type, {})
    owner_id = owner_resources.get(aic.resource.fixture_ref) if isinstance(owner_resources, dict) else None
    other_id = other_resources.get(aic.resource.fixture_ref) if isinstance(other_resources, dict) else None
    resolved_params: dict[str, Any] = {}
    for key, value in params.items():
        if value == "$resource.id":
            if owner_id is None:
                raise ValueError("Fixture map is missing the owner's resource ID")
            resolved_params[key] = owner_id
        elif value == "$resource.other_id":
            if other_id is None:
                raise ValueError("Fixture map is missing the other principal's resource ID")
            resolved_params[key] = other_id
        else:
            resolved_params[key] = value

    actual_principal = aic.positive_control.as_principal
    if counterfactual:
        mutation = aic.counterfactual.mutation
        if mutation.dimension == "principal":
            actual_principal = mutation.to_value
        elif mutation.dimension == "object_id":
            if owner_id is None or other_id is None or owner_id == other_id:
                raise ValueError("Object-ID mutation must resolve to distinct resources in the ownership map")
            path_params = {part[1:-1] for part in aic.target.path.split("/") if part.startswith("{") and part.endswith("}")}
            candidates = [name for name in path_params if name in resolved_params]
            if len(candidates) != 1:
                raise ValueError("Object-ID mutation must resolve to exactly one declared path parameter")
            resolved_params[candidates[0]] = other_id

    path = render_path(aic.target.path, resolved_params)
    if counterfactual:
        before_path = render_path(aic.target.path, {key: (owner_id if value == "$resource.id" else owner_id if value == "$resource.other_id" else value)
                                                       for key, value in params.items()})
        before = {"principal": aic.positive_control.as_principal, "path": before_path,
                  "query": dict(aic.positive_control.request.query_params), "body": aic.positive_control.request.body}
        after = {"principal": actual_principal, "path": path, "query": query, "body": body}
        if aic.counterfactual.mutation.dimension == "principal":
            allowed_path = "$.principal"
        else:
            allowed_path = "$.path"
            before["principal"] = after["principal"]
        assert_minimal_mutation(before, after, dimension=aic.counterfactual.mutation.dimension, allowed_path=allowed_path)
    return RenderedRequest(actual_principal, aic.target.method, path, query, body)


def render_path(template: str, params: dict[str, Any]) -> str:
    result = template
    for name, value in params.items():
        token = "{" + name + "}"
        if token in result:
            result = result.replace(token, str(value))
    if "{" in result or "}" in result:
        raise ValueError("Path template contains an unresolved parameter")
    return result
