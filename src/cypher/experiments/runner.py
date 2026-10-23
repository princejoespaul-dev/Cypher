"""Reproducible experiment manifest and output hashing."""
from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.experiments.models import ExperimentConfig


@dataclass(frozen=True, slots=True)
class ExperimentRun:
    experiment_id: UUID
    manifest: dict[str, Any]
    manifest_hash: str
    results: dict[str, Any]
    results_hash: str


class ExperimentRunner:
    def __init__(self, *, repository_root: str | Path = ".") -> None:
        self.root = Path(repository_root)

    def create_manifest(self, config: ExperimentConfig, *, image_digests: dict[str, str], prompt_hashes: dict[str, str],
                        model_ids: dict[str, str], embedding_version: str | None, case_library_snapshot_id: str | None,
                        lockfile_path: str = "uv.lock", git_commit: str | None = None) -> dict[str, Any]:
        lock_path = self.root / lockfile_path
        lock_hash = hashlib.sha256(lock_path.read_bytes()).hexdigest() if lock_path.exists() else None
        manifest = {
            "experiment_id": str(config.experiment_id), "config": config.model_dump(mode="json"),
            "git_commit": git_commit or os.getenv("GIT_COMMIT", "unknown"), "lockfile_sha256": lock_hash,
            "python_version": platform.python_version(), "platform": platform.platform(),
            "image_digests": dict(sorted(image_digests.items())), "prompt_hashes": dict(sorted(prompt_hashes.items())),
            "model_ids": dict(sorted(model_ids.items())), "embedding_version": embedding_version,
            "case_library_snapshot_id": case_library_snapshot_id, "ground_truth_sha256": config.ground_truth_sha256,
            "recorded_outputs_replayed": True,
        }
        return manifest

    def run(self, config: ExperimentConfig, *, manifest: dict[str, Any],
            evaluate: Callable[[str, int, int], dict[str, Any]]) -> ExperimentRun:
        arms: dict[str, list[dict[str, Any]]] = {}
        for arm in config.arms:
            arm_results: list[dict[str, Any]] = []
            for seed in config.seeds:
                for repeat in range(config.repeat_count):
                    # The evaluator receives all random inputs explicitly, avoiding hidden RNG state.
                    arm_results.append({"seed": seed, "repeat": repeat, **evaluate(arm, seed, repeat)})
            arms[arm] = arm_results
        results: dict[str, Any] = {"experiment_id": str(config.experiment_id), "arms": arms}
        manifest_hash = sha256_hex(canonical_json_bytes(manifest, permit_float=True))
        results["manifest_hash"] = manifest_hash
        results_hash = sha256_hex(canonical_json_bytes(results, permit_float=True))
        return ExperimentRun(config.experiment_id, manifest, manifest_hash, results, results_hash)

    @staticmethod
    def export(run: ExperimentRun, path: str | Path) -> Path:
        output = {"manifest": run.manifest, "manifest_hash": run.manifest_hash, "results": run.results, "results_hash": run.results_hash}
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_suffix(destination.suffix + ".tmp")
        temp.write_bytes(canonical_json_bytes(output, permit_float=True))
        temp.replace(destination)
        return destination


def verify_export(path: str | Path) -> bool:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest_hash = sha256_hex(canonical_json_bytes(payload["manifest"], permit_float=True))
    expected_results_hash = sha256_hex(canonical_json_bytes(payload["results"], permit_float=True))
    return manifest_hash == payload["manifest_hash"] and expected_results_hash == payload["results_hash"]
