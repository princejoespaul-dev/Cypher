"""Docker image builder that pins source commits and emits immutable image digests."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class BuiltImage:
    build_id: UUID
    project_id: UUID
    target_id: UUID
    label: str
    git_ref: str
    image_digest: str
    image_id: str
    repository_digests: tuple[str, ...]


class DockerBuildManager:
    def __init__(self, *, build_root: str | Path, docker_client: object | None = None) -> None:
        self._root = Path(build_root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        if docker_client is None:
            try:
                import docker  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError("Install the pinned docker SDK to build sandbox images") from exc
            docker_client = docker.from_env()
        self._client = docker_client

    def build_variant(self, *, project_id: UUID, target_id: UUID, context_path: str | Path, git_ref: str,
                      label: str, base_image_ref: str, dockerfile: str = "Dockerfile") -> BuiltImage:
        context = Path(context_path).resolve()
        if self._root not in context.parents and context != self._root:
            raise ValueError("Docker build context must be inside the configured build root")
        if not context.is_dir():
            raise ValueError("Docker build context directory does not exist")
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", base_image_ref):
            raise ValueError("Base image must be a fully qualified OCI image reference pinned by @sha256 digest")
        if not re.fullmatch(r"[a-fA-F0-9]{7,40}|refs/tags/[A-Za-z0-9_.-]+", git_ref):
            raise ValueError("git_ref must be a commit hash or a fully qualified tag ref")
        if label not in {"vulnerable", "fixed", "partial_fix", "over_blocking", "reintroduced", "other"}:
            raise ValueError("Unknown build variant label")
        image, _logs = self._client.images.build(path=str(context), dockerfile=dockerfile, rm=True, pull=False,
            buildargs={"CYPHER_VARIANT": label, "PYTHON_BASE_IMAGE": base_image_ref},
            labels={"cypher.project_id": str(project_id), "cypher.target_id": str(target_id),
                    "cypher.build_label": label, "cypher.git_ref": git_ref})
        image.reload()
        image_id = str(image.id)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise RuntimeError("Docker daemon did not return an immutable SHA-256 image ID")
        repo_digests = tuple(sorted(str(v) for v in image.attrs.get("RepoDigests", []) if isinstance(v, str)))
        return BuiltImage(uuid4(), project_id, target_id, label, git_ref, image_id, image_id, repo_digests)
