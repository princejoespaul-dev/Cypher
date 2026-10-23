"""Job contracts and worker entrypoints. Long-running work never runs inside API requests."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable
from uuid import UUID, uuid4

from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.core.errors import Conflict, NotFound


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class JobRecord:
    job_id: UUID
    project_id: UUID
    kind: str
    state: JobState
    payload: dict[str, Any]
    payload_hash: str
    idempotency_key: str
    attempts: int
    created_at: datetime
    updated_at: datetime
    result: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None


class IdempotentJobStore:
    """Small thread-safe development store. Production persistence belongs in PostgreSQL + Arq."""
    def __init__(self) -> None:
        from threading import RLock
        self._lock = RLock()
        self._jobs: dict[UUID, JobRecord] = {}
        self._keys: dict[tuple[UUID, str, str], UUID] = {}

    def enqueue(self, *, project_id: UUID, kind: str, payload: dict[str, Any], idempotency_key: str) -> JobRecord:
        if len(idempotency_key) < 8 or len(idempotency_key) > 128:
            raise ValueError("Idempotency-Key must be between 8 and 128 characters")
        payload_hash = sha256_hex(canonical_json_bytes(payload, permit_float=True))
        key = (project_id, kind, idempotency_key)
        with self._lock:
            prior_id = self._keys.get(key)
            if prior_id is not None:
                prior = self._jobs[prior_id]
                if prior.payload_hash != payload_hash:
                    raise Conflict("Idempotency-Key was already used with a different payload", code="idempotency.conflict")
                return prior
            now = datetime.now(timezone.utc)
            record = JobRecord(uuid4(), project_id, kind, JobState.QUEUED, payload, payload_hash, idempotency_key, 0, now, now)
            self._jobs[record.job_id] = record
            self._keys[key] = record.job_id
            return record

    def claim(self, job_id: UUID) -> JobRecord:
        with self._lock:
            row = self._jobs.get(job_id)
            if row is None:
                raise NotFound("Job not found")
            if row.state != JobState.QUEUED:
                raise Conflict("Only queued jobs may be claimed")
            updated = JobRecord(**{**_asdict(row), "state": JobState.RUNNING, "attempts": row.attempts + 1, "updated_at": datetime.now(timezone.utc)})
            self._jobs[job_id] = updated
            return updated

    def finish(self, job_id: UUID, *, result: dict[str, Any] | None = None, error_code: str | None = None, error_message: str | None = None) -> JobRecord:
        with self._lock:
            row = self._jobs.get(job_id)
            if row is None:
                raise NotFound("Job not found")
            if row.state != JobState.RUNNING:
                raise Conflict("Only running jobs may be finished")
            state = JobState.SUCCEEDED if error_code is None else JobState.FAILED
            updated = JobRecord(**{**_asdict(row), "state": state, "updated_at": datetime.now(timezone.utc),
                                   "result": result, "error_code": error_code, "error_message": error_message})
            self._jobs[job_id] = updated
            return updated

    def get(self, job_id: UUID, project_id: UUID) -> JobRecord | None:
        with self._lock:
            row = self._jobs.get(job_id)
            return row if row and row.project_id == project_id else None


def _asdict(row: JobRecord) -> dict[str, Any]:
    return {name: getattr(row, name) for name in row.__dataclass_fields__}


async def run_job(ctx: dict[str, Any], job_id: str, handler_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Arq-compatible task wrapper; no arbitrary callable names from the request are accepted."""
    handlers: dict[str, Callable[..., Any]] = ctx.get("handlers", {})
    handler = handlers.get(handler_name)
    if handler is None:
        raise RuntimeError(f"Unregistered job handler: {handler_name}")
    result = handler(**payload)
    if hasattr(result, "__await__"):
        result = await result
    return result if isinstance(result, dict) else {"result": result}
