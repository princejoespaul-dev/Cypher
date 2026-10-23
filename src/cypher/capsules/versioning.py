"""Immutable in-memory capsule version lifecycle and pure schema upgrades."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from threading import RLock
from uuid import UUID, uuid4

from cypher.capsules.canonical import capsule_content_hash, capsule_fingerprint
from cypher.capsules.models import AIC


class CapsuleStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


@dataclass(frozen=True, slots=True)
class CapsuleVersion:
    capsule_id: UUID
    capsule_version_id: UUID
    project_id: UUID
    version: int
    schema_version: str
    content: AIC
    content_hash: str
    fingerprint: str
    authored_by: str
    suggestion_id: UUID | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CapsuleStatusEvent:
    capsule_version_id: UUID
    status: CapsuleStatus
    actor_id: UUID
    created_at: datetime


class CapsuleStore:
    def __init__(self) -> None:
        self._versions: dict[UUID, list[CapsuleVersion]] = {}
        self._events: dict[UUID, list[CapsuleStatusEvent]] = {}
        self._lock = RLock()

    def create(self, project_id: UUID, actor_id: UUID, content: AIC) -> CapsuleVersion:
        capsule_id = uuid4()
        return self._new_version(capsule_id, project_id, actor_id, content)

    def new_version(self, capsule_id: UUID, project_id: UUID, actor_id: UUID, content: AIC) -> CapsuleVersion:
        with self._lock:
            if capsule_id not in self._versions:
                raise KeyError("Capsule does not exist")
            if self._versions[capsule_id][0].project_id != project_id:
                raise KeyError("Capsule does not exist")
        return self._new_version(capsule_id, project_id, actor_id, content)

    def _new_version(self, capsule_id: UUID, project_id: UUID, actor_id: UUID, content: AIC) -> CapsuleVersion:
        with self._lock:
            history = self._versions.setdefault(capsule_id, [])
            version = CapsuleVersion(capsule_id, uuid4(), project_id, len(history) + 1, content.aic_version,
                                     content, capsule_content_hash(content), capsule_fingerprint(content),
                                     content.provenance.authored_by, content.provenance.suggestion_id, datetime.now(timezone.utc))
            history.append(version)
            self._events[version.capsule_version_id] = [CapsuleStatusEvent(version.capsule_version_id, CapsuleStatus.DRAFT, actor_id, datetime.now(timezone.utc))]
            return version

    def transition(self, version_id: UUID, project_id: UUID, actor_id: UUID, status: CapsuleStatus) -> CapsuleStatusEvent:
        allowed = {CapsuleStatus.DRAFT: {CapsuleStatus.VALIDATED}, CapsuleStatus.VALIDATED: {CapsuleStatus.APPROVED, CapsuleStatus.DRAFT},
                   CapsuleStatus.APPROVED: {CapsuleStatus.DEPRECATED}, CapsuleStatus.DEPRECATED: set()}
        with self._lock:
            target = next((v for versions in self._versions.values() for v in versions if v.capsule_version_id == version_id and v.project_id == project_id), None)
            if target is None:
                raise KeyError("Capsule version does not exist")
            events = self._events[version_id]
            current = events[-1].status
            if status not in allowed[current]:
                raise ValueError(f"Invalid capsule status transition {current} -> {status}")
            if status == CapsuleStatus.APPROVED and target.authored_by == "guidance" and target.suggestion_id is None:
                raise ValueError("AI-generated capsule is missing its suggestion reference")
            event = CapsuleStatusEvent(version_id, status, actor_id, datetime.now(timezone.utc))
            events.append(event)
            return event

    def status(self, version_id: UUID) -> CapsuleStatus | None:
        with self._lock:
            events = self._events.get(version_id)
            return events[-1].status if events else None

    def get(self, version_id: UUID, project_id: UUID) -> CapsuleVersion | None:
        with self._lock:
            return next((v for versions in self._versions.values() for v in versions if v.capsule_version_id == version_id and v.project_id == project_id), None)

    def history(self, capsule_id: UUID, project_id: UUID) -> tuple[CapsuleVersion, ...]:
        with self._lock:
            return tuple(v for v in self._versions.get(capsule_id, ()) if v.project_id == project_id)


def upgrade_aic_v1_to_v1(content: dict[str, object]) -> dict[str, object]:
    """Explicit no-op migration for current 1.0 schema; returns a copy for new versioning."""
    import copy
    result = copy.deepcopy(content)
    result["aic_version"] = "1.0"
    return result
