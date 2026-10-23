"""Strict Authorization Invariant Capsule (AIC) contracts."""
from __future__ import annotations

from typing import Annotated, Literal
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
MutationDimension = Literal["principal", "object_id"]


class TargetOperation(StrictModel):
    operation_id: Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")]
    method: HttpMethod
    path: Annotated[str, Field(min_length=1, max_length=2048)]

    @field_validator("path")
    @classmethod
    def path_must_be_origin_form(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value:
            raise ValueError("path must be an origin-form path template beginning with one slash")
        if ".." in value.split("/"):
            raise ValueError("path traversal segments are not allowed")
        return value


class PolicyReference(StrictModel):
    policy_version_id: UUID
    rule_id: Annotated[str, Field(min_length=1, max_length=160)]


class Principals(StrictModel):
    owner: Annotated[str, Field(min_length=1, max_length=120)]
    other: Annotated[str, Field(min_length=1, max_length=120)]

    @model_validator(mode="after")
    def distinct_principals(self) -> "Principals":
        if self.owner == self.other:
            raise ValueError("owner and other principals must differ")
        return self


class ResourceReference(StrictModel):
    type: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")]
    fixture_ref: Annotated[str, Field(min_length=1, max_length=200)]


class RequestTemplate(StrictModel):
    path_params: dict[str, JsonValue] = Field(default_factory=dict)
    query_params: dict[str, JsonValue] = Field(default_factory=dict)
    body: dict[str, JsonValue] | list[JsonValue] | None = None


class PositiveExpectations(StrictModel):
    status_in: list[int] = Field(min_length=1, max_length=20)
    fingerprint_fields: list[Annotated[str, Field(min_length=3, max_length=512)]] = Field(default_factory=list, max_length=40)

    @field_validator("status_in")
    @classmethod
    def status_codes_are_http(cls, value: list[int]) -> list[int]:
        if any(status < 100 or status > 599 for status in value):
            raise ValueError("status_in values must be valid HTTP status codes")
        return list(dict.fromkeys(value))


class PositiveControl(StrictModel):
    as_principal: Annotated[str, Field(alias="as", min_length=1, max_length=120)]
    request: RequestTemplate
    expect: PositiveExpectations


class Mutation(StrictModel):
    dimension: MutationDimension
    from_value: Annotated[str, Field(alias="from", min_length=1, max_length=200)]
    to_value: Annotated[str, Field(alias="to", min_length=1, max_length=200)]

    @model_validator(mode="after")
    def mutation_changes_subject(self) -> "Mutation":
        if self.from_value == self.to_value:
            raise ValueError("a mutation must change its from/to value")
        return self


class DenialExpectations(StrictModel):
    status_in: list[int] = Field(min_length=1, max_length=20)
    leak_check: Literal["fingerprint_absent"] = "fingerprint_absent"

    @field_validator("status_in")
    @classmethod
    def status_codes_are_http(cls, value: list[int]) -> list[int]:
        if any(status < 100 or status > 599 for status in value):
            raise ValueError("status_in values must be valid HTTP status codes")
        return list(dict.fromkeys(value))


class Counterfactual(StrictModel):
    mutation: Mutation
    expect_denied: DenialExpectations


class StateOracle(StrictModel):
    enabled: bool = False
    probes: list[Annotated[str, Field(min_length=1, max_length=120)]] = Field(default_factory=list, max_length=20)
    expect: Literal["unchanged"] = "unchanged"

    @model_validator(mode="after")
    def enabled_requires_probes(self) -> "StateOracle":
        if self.enabled and not self.probes:
            raise ValueError("state oracle must name at least one probe when enabled")
        if not self.enabled and self.probes:
            raise ValueError("disabled state oracle must not declare probes")
        return self


class Safety(StrictModel):
    sandbox_only: bool = True
    destructive: bool = False


class Provenance(StrictModel):
    authored_by: Literal["human", "guidance"] = "human"
    suggestion_id: UUID | None = None


class AIC(StrictModel):
    aic_version: Literal["1.0"] = "1.0"
    title: Annotated[str, Field(min_length=1, max_length=240)]
    vuln_class: Literal["BOLA", "IDOR"]
    target: TargetOperation
    policy: PolicyReference
    principals: Principals
    resource: ResourceReference
    positive_control: PositiveControl
    counterfactual: Counterfactual
    state_oracle: StateOracle = Field(default_factory=StateOracle)
    safety: Safety = Field(default_factory=Safety)
    provenance: Provenance = Field(default_factory=Provenance)
    ignore_fields: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def cross_field_invariants(self) -> "AIC":
        if self.positive_control.as_principal != self.principals.owner:
            raise ValueError("positive_control.as must refer to principals.owner")
        path_parameters = set(re.findall(r"\{([^{}]+)\}", self.target.path))
        declared_parameters = set(self.positive_control.request.path_params)
        if path_parameters != declared_parameters:
            raise ValueError("positive_control.path_params must exactly match path placeholders")
        if any(value == "$resource.other_id" for value in self.positive_control.request.path_params.values()):
            raise ValueError("positive_control must use the owner's resource identifier")
        mutation = self.counterfactual.mutation
        if mutation.dimension == "principal":
            if mutation.from_value != self.principals.owner or mutation.to_value != self.principals.other:
                raise ValueError("principal mutation must change owner to other")
        elif mutation.from_value != "$resource.id" or mutation.to_value != "$resource.other_id":
            raise ValueError("object_id mutation must change $resource.id to $resource.other_id")
        if self.provenance.authored_by == "guidance" and self.provenance.suggestion_id is None:
            raise ValueError("guidance-authored capsules must reference their suggestion")
        if self.provenance.authored_by == "human" and self.provenance.suggestion_id is not None:
            raise ValueError("human-authored capsules must not reference an AI suggestion")
        return self


def aic_json_schema() -> dict[str, object]:
    """Return JSON Schema generated from the source-of-truth Pydantic model."""
    return AIC.model_json_schema(by_alias=True)
