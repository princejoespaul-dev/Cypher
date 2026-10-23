"""Strict target, build, principal and fixture metadata."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BuildLabel(StrEnum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    PARTIAL_FIX = "partial_fix"
    OVER_BLOCKING = "over_blocking"
    REINTRODUCED = "reintroduced"
    OTHER = "other"


class Target(StrictModel):
    target_id: UUID
    project_id: UUID
    name: Annotated[str, Field(min_length=1, max_length=160)]
    base_url: str
    host_allowlist: tuple[str, ...]
    sandbox_only: bool = True
    openapi_spec_ref: str | None = None
    created_at: datetime

    @field_validator("host_allowlist")
    @classmethod
    def normalized_hosts(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(host.strip().lower().rstrip(".") for host in hosts)
        if not normalized or any(not host or "/" in host or ":" in host for host in normalized):
            raise ValueError("host_allowlist must contain hostname-only entries")
        if len(set(normalized)) != len(normalized):
            raise ValueError("host_allowlist must not contain duplicates")
        return normalized


class TargetBuild(StrictModel):
    build_id: UUID
    project_id: UUID
    target_id: UUID
    label: BuildLabel
    git_ref: str
    image_digest: str
    reintroduction_patch_ref: str | None = None
    created_at: datetime

    @field_validator("image_digest")
    @classmethod
    def digest_must_be_pinned(cls, value: str) -> str:
        import re
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("Build must reference an immutable sha256 image digest, never a tag")
        return value


class Principal(StrictModel):
    principal_id: UUID
    target_id: UUID
    name: Annotated[str, Field(min_length=1, max_length=120)]
    role: Annotated[str, Field(min_length=1, max_length=80)]
    credential_ref: Annotated[str, Field(min_length=1, max_length=240)]
    login_flow: dict[str, str]

    @field_validator("credential_ref")
    @classmethod
    def credential_is_a_reference(cls, value: str) -> str:
        if value.startswith(("Bearer ", "eyJ")) or len(value) > 512:
            raise ValueError("credential_ref must be a secret-store reference, not a secret value")
        return value
