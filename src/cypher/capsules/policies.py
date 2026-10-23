"""Small immutable versioned policy registry; not an API enforcement engine."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from uuid import UUID, uuid4

from cypher.core.canonical import canonical_json_bytes, sha256_hex


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    resource_type: str
    action: str
    allow_when: str


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    policy_version_id: UUID
    target_id: UUID
    version: int
    rules: tuple[PolicyRule, ...]
    content_hash: str
    created_at: datetime


class PolicyRegistry:
    def __init__(self) -> None:
        self._by_target: dict[UUID, list[PolicyVersion]] = {}
        self._lock = RLock()

    def create_version(self, target_id: UUID, rules: tuple[PolicyRule, ...]) -> PolicyVersion:
        if not rules or len({rule.rule_id for rule in rules}) != len(rules):
            raise ValueError("A policy version needs unique rule IDs")
        payload = [{"rule_id": r.rule_id, "resource_type": r.resource_type, "action": r.action, "allow_when": r.allow_when} for r in rules]
        with self._lock:
            versions = self._by_target.setdefault(target_id, [])
            record = PolicyVersion(uuid4(), target_id, len(versions) + 1, rules, sha256_hex(canonical_json_bytes(payload)), datetime.now(timezone.utc))
            versions.append(record)
            return record

    def get(self, policy_version_id: UUID) -> PolicyVersion | None:
        with self._lock:
            for versions in self._by_target.values():
                for record in versions:
                    if record.policy_version_id == policy_version_id:
                        return record
        return None

    def versions_for(self, target_id: UUID) -> tuple[PolicyVersion, ...]:
        with self._lock:
            return tuple(self._by_target.get(target_id, ()))
