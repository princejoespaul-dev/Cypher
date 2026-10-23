"""Project-scoped in-memory target/build/principal registry for local development."""
from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from uuid import UUID, uuid4

from cypher.targets.models import Principal, Target, TargetBuild


class TargetRegistry:
    def __init__(self) -> None:
        self._targets: dict[UUID, Target] = {}
        self._builds: dict[UUID, TargetBuild] = {}
        self._principals: dict[UUID, Principal] = {}
        self._lock = RLock()

    def create_target(self, *, project_id: UUID, name: str, base_url: str, host_allowlist: tuple[str, ...], openapi_spec_ref: str | None = None) -> Target:
        from urllib.parse import urlsplit
        parsed = urlsplit(base_url)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Sandbox target base_url must use plain HTTP inside its isolated network and contain no credentials")
        if parsed.hostname.lower() not in {h.lower().rstrip(".") for h in host_allowlist}:
            raise ValueError("base_url hostname must be in host_allowlist")
        record = Target(target_id=uuid4(), project_id=project_id, name=name, base_url=base_url.rstrip("/"),
                        host_allowlist=host_allowlist, sandbox_only=True, openapi_spec_ref=openapi_spec_ref,
                        created_at=datetime.now(timezone.utc))
        with self._lock:
            self._targets[record.target_id] = record
        return record

    def add_build(self, *, target_id: UUID, project_id: UUID, label: str, git_ref: str, image_digest: str, reintroduction_patch_ref: str | None = None) -> TargetBuild:
        target = self.get_target(target_id, project_id)
        if target is None:
            raise KeyError("Target not found")
        record = TargetBuild(build_id=uuid4(), project_id=project_id, target_id=target_id, label=label, git_ref=git_ref,
                             image_digest=image_digest, reintroduction_patch_ref=reintroduction_patch_ref,
                             created_at=datetime.now(timezone.utc))
        with self._lock:
            self._builds[record.build_id] = record
        return record

    def add_principal(self, principal: Principal, project_id: UUID) -> Principal:
        target = self.get_target(principal.target_id, project_id)
        if target is None:
            raise KeyError("Target not found")
        with self._lock:
            if any(p.target_id == principal.target_id and p.name == principal.name for p in self._principals.values()):
                raise ValueError("Principal name already exists for target")
            self._principals[principal.principal_id] = principal
        return principal


    def list_targets(self, project_id: UUID) -> tuple[Target, ...]:
        with self._lock:
            return tuple(sorted((t for t in self._targets.values() if t.project_id == project_id), key=lambda t: (t.name, str(t.target_id))))

    def get_target(self, target_id: UUID, project_id: UUID) -> Target | None:
        with self._lock:
            value = self._targets.get(target_id)
            return value if value and value.project_id == project_id else None

    def get_build(self, build_id: UUID, project_id: UUID) -> TargetBuild | None:
        with self._lock:
            value = self._builds.get(build_id)
            return value if value and value.project_id == project_id else None

    def builds_for_target(self, target_id: UUID, project_id: UUID) -> tuple[TargetBuild, ...]:
        with self._lock:
            return tuple(b for b in self._builds.values() if b.target_id == target_id and b.project_id == project_id)

    def principals_for_target(self, target_id: UUID, project_id: UUID) -> tuple[Principal, ...]:
        with self._lock:
            target = self.get_target(target_id, project_id)
            return tuple(p for p in self._principals.values() if target and p.target_id == target_id)
