"""Hashed API-key validation and project/role scoping primitives."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from cypher.core.errors import Forbidden, Unauthorized


class Role(StrEnum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass(frozen=True, slots=True)
class ApiKeyPrincipal:
    user_id: UUID
    project_id: UUID
    role: Role
    key_hash: str
    name: str = "api-key"


class ApiKeyRegistry:
    """In-memory adapter; replace storage with the Phase 1 api_keys/memberships tables."""
    def __init__(self) -> None:
        self._records: dict[str, ApiKeyPrincipal] = {}

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def register(self, raw_key: str, *, user_id: UUID, project_id: UUID, role: Role, name: str = "api-key") -> ApiKeyPrincipal:
        if len(raw_key) < 16:
            raise ValueError("API keys must contain at least 16 characters")
        digest = self.hash_key(raw_key)
        principal = ApiKeyPrincipal(user_id, project_id, role, digest, name)
        self._records[digest] = principal
        return principal

    def authenticate(self, raw_key: str | None) -> ApiKeyPrincipal:
        if not raw_key:
            raise Unauthorized("Bearer API key is required")
        digest = self.hash_key(raw_key)
        for stored_hash, principal in self._records.items():
            if hmac.compare_digest(stored_hash, digest):
                return principal
        raise Unauthorized("Bearer API key is invalid")


def require_role(actual: Role, *allowed: Role) -> None:
    if actual not in set(allowed):
        raise Forbidden("The caller's role is not permitted to perform this operation")
