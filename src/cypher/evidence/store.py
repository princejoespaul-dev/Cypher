"""Content-addressed evidence blob stores with no deletion API."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Protocol
from uuid import UUID

from cypher.core.canonical import canonical_json_bytes


class EvidenceStore(Protocol):
    def put_bytes(self, *, project_id: UUID, data: bytes, content_type: str) -> str: ...
    def read_bytes(self, *, project_id: UUID, content_sha256: str) -> bytes | None: ...


class FileEvidenceStore:
    """Local development adapter. Project IDs partition access; blobs are immutable by hash."""
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, *, project_id: UUID, data: bytes, content_type: str) -> str:
        digest = hashlib.sha256(data).hexdigest()
        directory = self.root / str(project_id) / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / digest
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Evidence content-address collision or tampering detected")
            return digest
        fd, temp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temp_path, destination)
            except FileExistsError:
                if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("Evidence destination mismatch")
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
        meta = directory / f"{digest}.meta.json"
        if not meta.exists():
            meta.write_bytes(canonical_json_bytes({"content_sha256": digest, "content_type": content_type, "project_id": str(project_id)}))
        return digest

    def put_json(self, *, project_id: UUID, value: object) -> str:
        return self.put_bytes(project_id=project_id, data=canonical_json_bytes(value, permit_float=True), content_type="application/json")

    def read_bytes(self, *, project_id: UUID, content_sha256: str) -> bytes | None:
        import re
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            return None
        path = self.root / str(project_id) / content_sha256[:2] / content_sha256
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return None
        if hashlib.sha256(data).hexdigest() != content_sha256:
            raise RuntimeError("Evidence integrity check failed")
        return data

    def read_json(self, *, project_id: UUID, content_sha256: str) -> object | None:
        data = self.read_bytes(project_id=project_id, content_sha256=content_sha256)
        return json.loads(data) if data is not None else None
