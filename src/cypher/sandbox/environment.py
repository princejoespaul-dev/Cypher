"""Sandbox lifecycle with fail-closed networking, seed restoration and health gates.

The manager creates internal-only Docker networks and never publishes target ports on the
host. Seeding, health checking and restoration are injected because their correct behavior is
target-specific; without those callbacks an environment is not marked ready.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import ipaddress
from threading import RLock
from typing import Any, Callable
from uuid import UUID


class EnvironmentStatus(StrEnum):
    CREATING = "creating"
    SEEDING = "seeding"
    READY = "ready"
    RESETTING = "resetting"
    DESTROYED = "destroyed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SandboxEnvironment:
    environment_id: UUID
    project_id: UUID
    build_id: UUID
    image_digest: str
    docker_network_id: str
    network_subnet: str
    container_id: str
    status: EnvironmentStatus
    base_url: str
    seed_snapshot_hash: str
    ownership_map: dict[str, Any]
    sandbox_only: bool = True


class DockerEnvironmentManager:
    """Docker lifecycle adapter. Never silently treats an unseeded target as ready."""

    def __init__(self, *, network_subnet: str = "172.28.0.0/16", docker_client: object | None = None,
                 health_check: Callable[[str], bool] | None = None,
                 reset_runner: Callable[[SandboxEnvironment, int], str] | None = None) -> None:
        if docker_client is None:
            try:
                import docker  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError("Install the pinned 'docker' SDK to manage real sandbox environments") from exc
            docker_client = docker.from_env()
        self._client = docker_client
        try:
            self._network_pool = ipaddress.ip_network(network_subnet, strict=False)
        except ValueError as exc:
            raise ValueError("Sandbox network pool must be a valid private IPv4 CIDR") from exc
        if not isinstance(self._network_pool, ipaddress.IPv4Network) or not self._network_pool.is_private:
            raise ValueError("Sandbox network pool must be a private IPv4 CIDR")
        self._subnet_prefix = max(24, self._network_pool.prefixlen)
        if self._subnet_prefix > 24:
            raise ValueError("Sandbox network pool must contain at least one /24 target subnet")
        self._health_check = health_check
        self._reset_runner = reset_runner
        self._environments: dict[UUID, SandboxEnvironment] = {}
        self._allocated_subnets: set[str] = set()
        self._lock = RLock()

    def create(self, *, environment_id: UUID, project_id: UUID, build_id: UUID, image_digest: str,
               container_port: int, seed: Callable[[str], str | dict[str, Any]]) -> SandboxEnvironment:
        import re
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
            raise ValueError("Sandbox images must be pinned by SHA-256 digest")
        if not 1 <= container_port <= 65535:
            raise ValueError("Target container port is invalid")
        if self._health_check is None:
            raise RuntimeError("sandbox.health_check_unconfigured: a passing health-check callback is required")
        network = None
        container = None
        subnet = self._allocate_subnet(environment_id)
        try:
            network = self._client.networks.create(
                name=f"cypher-{environment_id.hex[:12]}", driver="bridge", internal=True,
                ipam={"Config": [{"Subnet": subnet}]},
                labels={"cypher.project_id": str(project_id), "cypher.environment_id": str(environment_id)},
            )
            image = self._client.images.get(image_digest)
            container = self._client.containers.run(
                image=image, detach=True, network=network.name, ports={}, read_only=True,
                cap_drop=["ALL"], security_opt=["no-new-privileges:true"], mem_limit="512m", nano_cpus=1_000_000_000,
                pids_limit=128, tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},
                labels={"cypher.project_id": str(project_id), "cypher.environment_id": str(environment_id)},
            )
            seeded = seed(container.id)
            if isinstance(seeded, str):
                snapshot_hash, ownership_map = seeded, {}
            elif isinstance(seeded, dict):
                snapshot_hash = seeded.get("seed_snapshot_hash")
                ownership_map = seeded.get("ownership_map", {})
            else:
                raise RuntimeError("sandbox.seed_failed: seeder must return a snapshot hash and optional ownership map")
            if not isinstance(snapshot_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot_hash):
                raise RuntimeError("sandbox.seed_failed: seeder returned an invalid snapshot hash")
            if not isinstance(ownership_map, dict):
                raise RuntimeError("sandbox.seed_failed: ownership map must be a JSON object")
            container.reload()
            base_url = f"http://{container.name}:{container_port}"
            if not self._health_check(base_url):
                raise RuntimeError("sandbox.health_check_failed: target did not pass its sandbox health check")
            env = SandboxEnvironment(environment_id, project_id, build_id, image_digest, network.id, subnet, container.id,
                                     EnvironmentStatus.READY, base_url, snapshot_hash, ownership_map, True)
            with self._lock:
                if environment_id in self._environments:
                    raise ValueError("Environment ID already exists")
                self._environments[environment_id] = env
            return env
        except Exception:
            if container is not None:
                try:
                    container.remove(force=True, v=True)
                except Exception:
                    pass
            if network is not None:
                try:
                    network.remove()
                except Exception:
                    pass
            with self._lock:
                self._allocated_subnets.discard(subnet)
            raise

    def get_environment(self, environment_id: UUID, project_id: UUID) -> SandboxEnvironment | None:
        """Return an environment only to its owning project, including non-ready states."""
        with self._lock:
            env = self._environments.get(environment_id)
            return env if env is not None and env.project_id == project_id else None

    def _allocate_subnet(self, environment_id: UUID) -> str:
        candidates = tuple(self._network_pool.subnets(new_prefix=self._subnet_prefix))
        if not candidates:
            raise RuntimeError("sandbox.subnet_pool_exhausted: no sandbox subnets are available")
        start = environment_id.int % len(candidates)
        with self._lock:
            for offset in range(len(candidates)):
                candidate = str(candidates[(start + offset) % len(candidates)])
                if candidate not in self._allocated_subnets:
                    self._allocated_subnets.add(candidate)
                    return candidate
        raise RuntimeError("sandbox.subnet_pool_exhausted: all configured target subnets are allocated")

    def get_base_url(self, environment_id: UUID) -> str:
        env = self._get_ready(environment_id)
        return env.base_url

    def is_sandbox(self, environment_id: UUID) -> bool:
        with self._lock:
            env = self._environments.get(environment_id)
            return bool(env and env.sandbox_only and env.status == EnvironmentStatus.READY)

    def reset_to_seed(self, environment_id: UUID, seed: int) -> str:
        if self._reset_runner is None:
            raise RuntimeError("sandbox.reset_unconfigured: no environment seed-reset handler is configured")
        env = self._get_ready(environment_id)
        with self._lock:
            resetting = SandboxEnvironment(**{**_asdict(env), "status": EnvironmentStatus.RESETTING})
            self._environments[environment_id] = resetting
        try:
            digest = self._reset_runner(resetting, seed)
            import re
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise RuntimeError("sandbox.reset_failed: reset runner did not return a valid snapshot hash")
            if digest != env.seed_snapshot_hash:
                raise RuntimeError("sandbox.reset_mismatch: restored database does not match the registered seed snapshot")
            with self._lock:
                ready = SandboxEnvironment(**{**_asdict(resetting), "status": EnvironmentStatus.READY, "seed_snapshot_hash": digest})
                self._environments[environment_id] = ready
            return digest
        except Exception:
            with self._lock:
                self._environments[environment_id] = SandboxEnvironment(**{**_asdict(resetting), "status": EnvironmentStatus.FAILED})
            raise

    def destroy(self, env: SandboxEnvironment) -> None:
        if not env.sandbox_only:
            raise ValueError("Refusing to destroy a non-sandbox environment through this manager")
        container = self._client.containers.get(env.container_id)
        network = self._client.networks.get(env.docker_network_id)
        container.remove(force=True, v=True)
        network.remove()
        with self._lock:
            current = self._environments.get(env.environment_id)
            if current is not None:
                self._environments[env.environment_id] = SandboxEnvironment(
                    **{**_asdict(current), "status": EnvironmentStatus.DESTROYED})
                self._allocated_subnets.discard(current.network_subnet)

    def _get_ready(self, environment_id: UUID) -> SandboxEnvironment:
        with self._lock:
            env = self._environments.get(environment_id)
        if env is None or not env.sandbox_only or env.status != EnvironmentStatus.READY:
            raise RuntimeError("env.not_sandbox: environment is missing, not ready or not sandbox-only")
        return env


def _asdict(env: SandboxEnvironment) -> dict[str, Any]:
    return {name: getattr(env, name) for name in env.__dataclass_fields__}
