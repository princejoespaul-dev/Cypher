"""Reference hash-chained audit writer and verifier.

Production deployments must persist an audit append and its domain mutation in one DB
transaction. This in-memory implementation is useful for tests and local development.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from cypher.core.canonical import canonical_json_bytes, sha256_hex


@dataclass(frozen=True, slots=True)
class AuditEntry:
    seq: int
    actor_id: UUID
    project_id: UUID
    action: str
    object_ref: str
    payload_sha256: str
    prev_hash: str
    hash: str
    created_at: datetime


class HashChainedAuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = RLock()

    def append(self, *, actor_id: UUID, project_id: UUID, action: str, object_ref: str, payload: dict[str, Any]) -> AuditEntry:
        with self._lock:
            previous = next((entry.hash for entry in reversed(self._entries) if entry.project_id == project_id), "0" * 64)
            payload_hash = sha256_hex(canonical_json_bytes(payload, permit_float=True))
            body = {"actor_id": str(actor_id), "action": action, "object_ref": object_ref,
                    "payload_sha256": payload_hash, "project_id": str(project_id), "seq": len(self._entries) + 1}
            digest = sha256_hex(previous.encode("ascii") + canonical_json_bytes(body))
            entry = AuditEntry(len(self._entries) + 1, actor_id, project_id, action, object_ref,
                               payload_hash, previous, digest, datetime.now(timezone.utc))
            self._entries.append(entry)
            return entry

    def entries(self, project_id: UUID | None = None) -> tuple[AuditEntry, ...]:
        with self._lock:
            items = self._entries if project_id is None else [e for e in self._entries if e.project_id == project_id]
            return tuple(items)

    def verify(self, project_id: UUID | None = None) -> bool:
        """Verify each project's chain independently, even when projects interleave."""
        with self._lock:
            tails: dict[UUID, str] = {}
            for entry in self._entries:
                if project_id is not None and entry.project_id != project_id:
                    continue
                expected_previous = tails.get(entry.project_id, "0" * 64)
                if entry.prev_hash != expected_previous:
                    return False
                body = {"actor_id": str(entry.actor_id), "action": entry.action, "object_ref": entry.object_ref,
                        "payload_sha256": entry.payload_sha256, "project_id": str(entry.project_id), "seq": entry.seq}
                expected = sha256_hex(entry.prev_hash.encode("ascii") + canonical_json_bytes(body))
                if expected != entry.hash:
                    return False
                tails[entry.project_id] = entry.hash
            return True
