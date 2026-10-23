"""FastAPI application factory and phase composition root.

Development mode uses explicitly non-durable in-memory adapters. Production must wire the
PostgreSQL repository, persistent API-key resolver, evidence store and sandbox worker before
it can be considered ready; the app refuses to report production-ready without them.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from cypher.capsules.models import AIC
from cypher.capsules.policies import PolicyRegistry, PolicyRule
from cypher.capsules.validators import ValidationContext, validate_aic_layers_1_to_4
from cypher.capsules.versioning import CapsuleStatus, CapsuleStore
from cypher.core.auth import ApiKeyRegistry, Role as CoreRole, require_role
from cypher.core.audit import HashChainedAuditLog
from cypher.core.errors import CypherError, Forbidden, Invalid, NotFound
from cypher.core.settings import Settings
from cypher.core.structured_logging import configure_json_logging
from cypher.guidance.llm.fake import FakeLLMClient
from cypher.guidance.pipeline import GuidanceService, SuggestRequest, SuggestionState
from cypher.history.service import HistoryService
from cypher.harness.adjudicator.rules import PureEvidenceAdjudicator
from cypher.harness.memory_repository import InMemoryPhase5Repository
from cypher.harness.phase5_errors import Phase5Error
from cypher.harness.phase5_models import Actor, Role as Phase5Role, ReadjudicateRequest
from cypher.harness.phase5_service import Phase5Services
from cypher.api.phase5_router import mount_phase5
from cypher.targets.models import Principal
from cypher.targets.registry import TargetRegistry
from cypher.capsules.canonical import capsule_fingerprint, capsule_content_hash
from cypher.experiments.models import ExperimentConfig
from cypher.experiments.runner import ExperimentRunner, verify_export
from cypher.core.canonical import canonical_json_bytes, sha256_hex
from cypher.sandbox.oracle import validate_select_probe, UnsafeProbe
from cypher.guidance.explain_service import ExplanationService

DEV_PROJECT_ID = UUID(int=1001)
DEV_USER_ID = UUID(int=1002)


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    base_url: str = Field(min_length=8, max_length=2048)
    host_allowlist: tuple[str, ...] = Field(min_length=1, max_length=20)
    openapi_spec_ref: str | None = None


class BuildCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str
    git_ref: str = Field(min_length=1, max_length=512)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reintroduction_patch_ref: str | None = None


class PrincipalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=80)
    credential_ref: str = Field(min_length=1, max_length=240)
    login_flow: dict[str, str]


class PolicyRuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1, max_length=160)
    resource_type: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=40)
    allow_when: str = Field(min_length=1, max_length=500)


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: tuple[PolicyRuleInput, ...] = Field(min_length=1, max_length=200)


class OpenAPICreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]


class FixtureCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fixture_refs: tuple[str, ...] = Field(min_length=1, max_length=200)


class CapsuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: UUID
    content: dict[str, Any]


class CapsuleVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: dict[str, Any]


class EnvironmentResetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = Field(default=0, ge=0, le=2**31 - 1)


class ReplayRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capsule_version_id: UUID
    build_ids: tuple[UUID, ...] = Field(min_length=1, max_length=10)
    repeats: int = Field(default=3, ge=1, le=10)

    @field_validator("build_ids")
    @classmethod
    def unique_build_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("build_ids must be unique")
        return value


class ExperimentRunRequest(BaseModel):
    """Client-supplied inputs are limited to an optional note; provenance is server-derived."""
    model_config = ConfigDict(extra="forbid")
    note: str = Field(default="", max_length=500)


class SuggestionRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: UUID
    operation_ids: tuple[str, ...] = Field(min_length=1, max_length=100)
    max_count: int = Field(default=5, ge=1, le=10)
    policy_version_id: UUID | None = None


class ExperimentCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config: dict[str, Any]


class OracleProbeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    sql: str = Field(min_length=1, max_length=8000)


class SuggestionDecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    comment: str = Field(default="", max_length=2000)


class ExplanationRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict_id: UUID


class HistoryRecommendationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: dict[str, Any]
    available_evidence_ids: tuple[str, ...] = Field(default=(), max_length=500)
    limit: int = Field(default=5, ge=1, le=5)


@dataclass
class JobInfo:
    job_id: UUID
    project_id: UUID
    state: str
    kind: str
    idempotency_key: str
    created_at: datetime
    result: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None


class LocalJobDispatcher:
    """Process-local idempotency adapter. Replace with Arq/Dramatiq for multi-process deployments."""
    def __init__(self) -> None:
        self.jobs: dict[UUID, JobInfo] = {}
        self.keys: dict[tuple[UUID, str], UUID] = {}

    def enqueue_regression_suite(self, *, suite_id: UUID, build_id: UUID, repeats: int, actor: Actor, idempotency_key: str) -> UUID:
        key = (actor.project_id, idempotency_key)
        if key in self.keys:
            existing_id = self.keys[key]
            existing = self.jobs[existing_id]
            expected = {"suite_id": str(suite_id), "build_id": str(build_id), "repeats": repeats}
            if existing.result != expected:
                raise CypherError("Idempotency-Key was already used with a different request", code="idempotency.conflict", status_code=409)
            return existing_id
        job_id = uuid4()
        self.jobs[job_id] = JobInfo(job_id, actor.project_id, "queued", "regression_suite", idempotency_key, datetime.now(timezone.utc),
                                    result={"suite_id": str(suite_id), "build_id": str(build_id), "repeats": repeats})
        self.keys[key] = job_id
        # No hidden replay is started here: a configured worker consumes the queued job.
        return job_id


def create_app(*, settings: Settings | None = None, api_keys: ApiKeyRegistry | None = None,
               phase5_repository: InMemoryPhase5Repository | None = None, production_dependencies_ready: bool = False,
               replay_submitter: Any | None = None, experiment_submitter: Any | None = None,
               environment_manager: Any | None = None, environment_factory: Any | None = None,
               llm_client: Any | None = None, capsule_dry_run: Any | None = None,
               job_dispatcher: Any | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.is_production and settings.guidance_enabled and llm_client is None:
        raise ValueError("Production guidance is enabled but no provider-backed LLMClient was injected")
    configure_json_logging()
    request_logger = logging.getLogger("cypher.http")
    key_registry = api_keys or ApiKeyRegistry()
    if api_keys is None:
        key_registry.register(settings.api_key, user_id=DEV_USER_ID, project_id=DEV_PROJECT_ID, role=CoreRole.ADMIN, name="local-development")
    app = FastAPI(title="CYPHER API", version="0.1.0", description="Sandbox-only invariant-linked authorization replay and evidence platform")
    app.state.settings = settings
    app.state.api_keys = key_registry
    app.state.ready = (not settings.is_production) or production_dependencies_ready
    app.state.started_at = time.monotonic()
    app.state.targets = TargetRegistry()
    app.state.capsules = CapsuleStore()
    app.state.policies = PolicyRegistry()
    app.state.audit = HashChainedAuditLog()
    app.state.openapi_operations = {}
    app.state.fixture_refs = {}
    app.state.oracle_probes = {}
    app.state.guidance_contexts = {}
    app.state.capsule_dry_run = capsule_dry_run
    app.state.llm_client = llm_client or FakeLLMClient()
    app.state.guidance = GuidanceService(
        llm=app.state.llm_client, validation_context=lambda project_id, target_id: _validation_context(app, project_id, target_id),
        dry_run=lambda capsule: callable(app.state.capsule_dry_run) and bool(app.state.capsule_dry_run(capsule)), token_cap=settings.guidance_daily_token_cap,
        cost_cap_usd=settings.guidance_daily_cost_cap_usd,
    )
    app.state.history = HistoryService()
    app.state.explanations = {}
    app.state.experiments = {}
    app.state.experiment_runner = ExperimentRunner()
    app.state.replay_submitter = replay_submitter
    app.state.experiment_submitter = experiment_submitter
    app.state.environment_manager = environment_manager
    app.state.environment_factory = environment_factory
    # No job is called queued unless a real dispatcher is injected; LocalJobDispatcher is for tests only.
    app.state.job_dispatcher = job_dispatcher
    app.state.phase5_repo = phase5_repository or InMemoryPhase5Repository()
    app.state.explanation_service = ExplanationService(repository=app.state.phase5_repo, llm=app.state.llm_client)
    app.state.phase5_services = None

    @app.middleware("http")
    async def authenticate_request(request: Request, call_next):
        started = time.monotonic()
        status_code = 500
        project_id = None
        try:
            if request.url.path in {"/", "/healthz", "/readyz", "/docs", "/redoc", "/openapi.json"}:
                response = await call_next(request)
                status_code = response.status_code
                return response
            token = request.headers.get("authorization", "")
            raw_key = token[7:].strip() if token.lower().startswith("bearer ") else request.headers.get("x-cypher-api-key")
            try:
                principal = app.state.api_keys.authenticate(raw_key)
            except CypherError as exc:
                response = _problem(exc.status_code, exc.code, exc.detail)
                status_code = response.status_code
                return response
            request.state.actor = Actor(user_id=principal.user_id, project_id=principal.project_id, role=Phase5Role(principal.role.value))
            request.state.core_role = principal.role
            project_id = str(principal.project_id)
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            request_logger.exception("request_failed", extra={"event": "request_failed", "http_method": request.method,
                "http_route": request.scope.get("path", ""), "http_status": status_code, "project_id": project_id,
                "duration_ms": round((time.monotonic() - started) * 1000, 3)})
            raise
        finally:
            request_logger.info("http_request", extra={"event": "http_request", "http_method": request.method,
                "http_route": request.scope.get("path", ""), "http_status": status_code, "project_id": project_id,
                "duration_ms": round((time.monotonic() - started) * 1000, 3)})

    @app.exception_handler(CypherError)
    async def cypher_error_handler(_request: Request, exc: CypherError):
        return _problem(exc.status_code, exc.code, exc.detail)

    @app.exception_handler(Phase5Error)
    async def phase5_error_handler(_request: Request, exc: Phase5Error):
        return _problem(exc.status_code, exc.code, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError):
        fields = [".".join(str(part) for part in error.get("loc", ())) for error in exc.errors()]
        detail = "Request validation failed" + (f" for: {', '.join(fields[:12])}" if fields else "")
        return _problem(422, "request.invalid", detail)

    @app.get("/", include_in_schema=False)
    def dashboard():
        """Serve the bundled CYPHER control-center UI from the repository checkout."""
        Path = __import__("pathlib").Path
        candidates = [
            Path(__file__).resolve().parents[3] / "dashboard" / "index.html",
            Path("/app/dashboard/index.html"),
        ]
        dashboard_file = next(
            (candidate for candidate in candidates if candidate.is_file()),
            None,
        )
        if dashboard_file is None:
            raise HTTPException(status_code=404, detail="Dashboard assets are not installed")
        return FileResponse(dashboard_file, media_type="text/html")

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": settings.service_name}

    @app.get("/readyz", tags=["health"])
    def readyz() -> JSONResponse:
        ready = bool(app.state.ready)
        payload = {"status": "ready" if ready else "not_ready", "mode": settings.environment}
        return JSONResponse(payload, status_code=200 if ready else 503)

    @app.get("/metrics", tags=["observability"], response_class=PlainTextResponse)
    def metrics(request: Request) -> str:
        actor = _actor(request)
        require_role(actor.role, CoreRole.ADMIN)
        uptime = max(0.0, time.monotonic() - app.state.started_at)
        return f"# HELP cypher_process_uptime_seconds Process uptime in seconds\n# TYPE cypher_process_uptime_seconds gauge\ncypher_process_uptime_seconds {uptime:.3f}\n"

    @app.post("/v1/targets", status_code=201, tags=["targets"])
    def create_target(payload: TargetCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        try:
            record = app.state.targets.create_target(project_id=actor.project_id, name=payload.name, base_url=payload.base_url,
                                                     host_allowlist=payload.host_allowlist, openapi_spec_ref=payload.openapi_spec_ref)
        except ValueError as exc:
            raise Invalid(str(exc), code="target.invalid") from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="target.created", object_ref=str(record.target_id), payload={"name": record.name, "sandbox_only": True})
        return record

    @app.get("/v1/targets", tags=["targets"])
    def list_targets(request: Request):
        actor = _actor(request)
        return app.state.targets.list_targets(actor.project_id)

    @app.get("/v1/targets/{target_id}", tags=["targets"])
    def get_target(target_id: UUID, request: Request):
        actor = _actor(request)
        target = app.state.targets.get_target(target_id, actor.project_id)
        if target is None:
            raise NotFound("Target not found", code="target.not_found")
        return target

    @app.post("/v1/targets/{target_id}/builds", status_code=201, tags=["targets"])
    def create_build(target_id: UUID, payload: BuildCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        try:
            record = app.state.targets.add_build(target_id=target_id, project_id=actor.project_id, label=payload.label,
                                                 git_ref=payload.git_ref, image_digest=payload.image_digest,
                                                 reintroduction_patch_ref=payload.reintroduction_patch_ref)
        except KeyError as exc:
            raise NotFound("Target was not found", code="target.not_found") from exc
        except ValueError as exc:
            raise Invalid(str(exc), code="build.invalid") from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="build.created", object_ref=str(record.build_id), payload={"label": record.label.value, "image_digest": record.image_digest})
        return record

    @app.get("/v1/targets/{target_id}/builds", tags=["targets"])
    def list_builds(target_id: UUID, request: Request):
        actor = _actor(request)
        if app.state.targets.get_target(target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        return app.state.targets.builds_for_target(target_id, actor.project_id)

    @app.post("/v1/targets/{target_id}/principals", status_code=201, tags=["targets"])
    def create_principal(target_id: UUID, payload: PrincipalCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        record = Principal(principal_id=uuid4(), target_id=target_id, name=payload.name, role=payload.role,
                           credential_ref=payload.credential_ref, login_flow=payload.login_flow)
        try:
            result = app.state.targets.add_principal(record, actor.project_id)
        except (KeyError, ValueError) as exc:
            raise Invalid(str(exc), code="principal.invalid") from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="principal.created", object_ref=str(result.principal_id), payload={"name": result.name, "credential_ref": result.credential_ref})
        return result

    @app.post("/v1/targets/{target_id}/openapi", status_code=201, tags=["targets"])
    def register_openapi(target_id: UUID, payload: OpenAPICreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        if app.state.targets.get_target(target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        document = payload.document
        paths = document.get("paths")
        if not isinstance(paths, dict) or not isinstance(document.get("openapi"), str):
            raise Invalid("A valid OpenAPI document with a paths object is required", code="openapi.invalid")
        ops: dict[str, dict[str, str]] = {}
        for path, methods in paths.items():
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            for method, definition in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(definition, dict):
                    continue
                operation_id = definition.get("operationId")
                if not isinstance(operation_id, str) or not operation_id.strip():
                    raise Invalid("Every in-scope operation must have an operationId", code="openapi.operation_id_required")
                if operation_id in ops:
                    raise Invalid("OpenAPI operationId values must be unique", code="openapi.operation_id_duplicate")
                ops[operation_id] = {"method": method.upper(), "path": path}
        app.state.openapi_operations[(actor.project_id, target_id)] = ops
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="target.openapi_registered", object_ref=str(target_id), payload={"operation_count": len(ops), "document_hash": sha256_hex(canonical_json_bytes(document, permit_float=True))})
        return {"target_id": str(target_id), "operation_count": len(ops), "operation_ids": sorted(ops)}

    @app.post("/v1/targets/{target_id}/fixtures", status_code=201, tags=["targets"])
    def register_fixtures(target_id: UUID, payload: FixtureCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        if app.state.targets.get_target(target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        refs = tuple(dict.fromkeys(payload.fixture_refs))
        app.state.fixture_refs[(actor.project_id, target_id)] = frozenset(refs)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="target.fixtures_registered", object_ref=str(target_id), payload={"fixture_count": len(refs)})
        return {"target_id": str(target_id), "fixture_count": len(refs), "fixture_refs": refs}

    @app.post("/v1/targets/{target_id}/oracle-probes", status_code=201, tags=["targets"])
    def register_oracle_probe(target_id: UUID, payload: OracleProbeCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        if app.state.targets.get_target(target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        try:
            safe_sql = validate_select_probe(payload.sql)
        except UnsafeProbe as exc:
            raise Invalid(str(exc), code="oracle.probe_unsafe") from exc
        key = (actor.project_id, target_id)
        probes = dict(app.state.oracle_probes.get(key, {}))
        if payload.name in probes and probes[payload.name] != safe_sql:
            raise Invalid("Probe names are immutable; choose a new name for changed SQL", code="oracle.probe_immutable", status_code=409)
        probes[payload.name] = safe_sql
        app.state.oracle_probes[key] = probes
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="oracle.probe_registered", object_ref=str(target_id), payload={"name": payload.name, "sql_sha256": sha256_hex(safe_sql.encode("utf-8"))})
        return {"target_id": str(target_id), "name": payload.name, "sql_sha256": sha256_hex(safe_sql.encode("utf-8"))}

    @app.post("/v1/targets/{target_id}/policies", status_code=201, tags=["policies"])
    def create_policy(target_id: UUID, payload: PolicyCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        if app.state.targets.get_target(target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        try:
            rules = tuple(PolicyRule(r.rule_id, r.resource_type, r.action, r.allow_when) for r in payload.rules)
            record = app.state.policies.create_version(target_id, rules)
        except ValueError as exc:
            raise Invalid(str(exc), code="policy.invalid") from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="policy.version_created", object_ref=str(record.policy_version_id), payload={"version": record.version, "content_hash": record.content_hash})
        return record

    @app.post("/v1/capsules", status_code=201, tags=["capsules"])
    def create_capsule(payload: CapsuleCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        if app.state.targets.get_target(payload.target_id, actor.project_id) is None:
            raise NotFound("Target not found", code="target.not_found")
        try:
            content = AIC.model_validate(payload.content)
        except Exception as exc:
            raise Invalid("AIC schema validation failed", code="aic.schema_invalid") from exc
        if content.provenance.authored_by != "human":
            raise Invalid("AI-authored capsules must be created only through an approved suggestion", code="capsule.ai_approval_bypass", status_code=403)
        record = app.state.capsules.create(actor.project_id, actor.user_id, content)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="capsule.version_created", object_ref=str(record.capsule_version_id), payload={"capsule_id": str(record.capsule_id), "version": record.version, "content_hash": record.content_hash})
        return record

    @app.post("/v1/capsules/{capsule_id}/versions", status_code=201, tags=["capsules"])
    def create_capsule_version(capsule_id: UUID, payload: CapsuleVersionCreate, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        history = app.state.capsules.history(capsule_id, actor.project_id)
        if not history:
            raise NotFound("Capsule not found", code="capsule.not_found")
        try:
            content = AIC.model_validate(payload.content)
        except Exception as exc:
            raise Invalid("AIC schema validation failed", code="aic.schema_invalid") from exc
        if content.provenance.authored_by != "human":
            raise Invalid("AI-authored versions must come from an approved suggestion", code="capsule.ai_approval_bypass", status_code=403)
        old_target = _find_target_for_capsule(app, actor.project_id, history[-1].content)
        new_target = _find_target_for_capsule(app, actor.project_id, content)
        if old_target is None or old_target != new_target:
            raise Invalid("A capsule version must preserve the registered target", code="capsule.target_changed")
        try:
            record = app.state.capsules.new_version(capsule_id, actor.project_id, actor.user_id, content)
        except (KeyError, ValueError) as exc:
            raise Invalid("Could not create capsule version", code="capsule.version_invalid") from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="capsule.version_created", object_ref=str(record.capsule_version_id), payload={"capsule_id": str(capsule_id), "version": record.version, "content_hash": record.content_hash})
        return record

    @app.get("/v1/capsules/{capsule_id}/versions/{version_number}", tags=["capsules"])
    def get_capsule_version(capsule_id: UUID, version_number: int, request: Request):
        actor = _actor(request)
        history = app.state.capsules.history(capsule_id, actor.project_id)
        record = next((item for item in history if item.version == version_number), None)
        if record is None:
            raise NotFound("Capsule version not found", code="capsule.version_not_found")
        status_value = app.state.capsules.status(record.capsule_version_id)
        return {"version": record, "status": status_value.value if status_value else "unknown"}

    @app.post("/v1/capsules/{version_id}/validate", tags=["capsules"])
    def validate_capsule(version_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        version = app.state.capsules.get(version_id, actor.project_id)
        if version is None:
            raise NotFound("Capsule version not found", code="capsule.not_found")
        target_context = _validation_context(app, actor.project_id, _find_target_for_capsule(app, actor.project_id, version.content))
        parsed, issues = validate_aic_layers_1_to_4(version.content.model_dump(mode="json", by_alias=True), target_context)
        if issues:
            return {"valid": False, "content_hash": version.content_hash, "fingerprint": version.fingerprint,
                    "errors": [{"layer": i.layer, "code": i.code, "message": i.message, "path": i.path} for i in issues]}
        status_event = app.state.capsules.transition(version_id, actor.project_id, actor.user_id, CapsuleStatus.VALIDATED)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="capsule.validated", object_ref=str(version_id), payload={"content_hash": version.content_hash})
        return {"valid": parsed is not None, "content_hash": version.content_hash, "fingerprint": version.fingerprint, "status": status_event.status.value, "errors": []}

    @app.post("/v1/capsules/{version_id}/approve", tags=["capsules"])
    def approve_capsule(version_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.REVIEWER)
        version = app.state.capsules.get(version_id, actor.project_id)
        if version is None:
            raise NotFound("Capsule version not found", code="capsule.not_found")
        if app.state.capsules.status(version_id) != CapsuleStatus.VALIDATED:
            raise Invalid("Only validated capsules can be approved", code="capsule.not_validated")
        # The real Phase 4 dry-run runner must be wired; no client-supplied boolean may bypass this gate.
        dry_run = getattr(app.state, "capsule_dry_run", None)
        if not callable(dry_run) or not dry_run(version):
            raise CypherError("Approval requires a passing sandbox dry run from the replay worker", code="capsule.dry_run_required", status_code=409)
        event = app.state.capsules.transition(version_id, actor.project_id, actor.user_id, CapsuleStatus.APPROVED)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="capsule.approved", object_ref=str(version_id), payload={"status": event.status.value})
        return {"capsule_version_id": str(version_id), "status": event.status.value}

    @app.post("/v1/guidance/suggestions", status_code=200, tags=["guidance"])
    def create_suggestions(payload: SuggestionRequestBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        if settings.is_production and not settings.guidance_enabled:
            raise CypherError("AI guidance is disabled by deployment configuration", code="llm.disabled", status_code=503)
        target = app.state.targets.get_target(payload.target_id, actor.project_id)
        if target is None:
            raise NotFound("Target not found", code="target.not_found")
        operations = app.state.openapi_operations.get((actor.project_id, payload.target_id), {})
        if not operations or any(op not in operations for op in payload.operation_ids):
            raise Invalid("Operation IDs must be selected from the registered OpenAPI document", code="guidance.operation_unknown")
        policy_versions = app.state.policies.versions_for(payload.target_id)
        if payload.policy_version_id is not None and not any(p.policy_version_id == payload.policy_version_id for p in policy_versions):
            raise NotFound("Policy version not found", code="policy.not_found")
        principals = app.state.targets.principals_for_target(payload.target_id, actor.project_id)
        context = {"operations": [{"operation_id": oid, **operations[oid]} for oid in payload.operation_ids],
                   "policy_rules": [{"policy_version_id": str(p.policy_version_id), "rules": [r.__dict__ if hasattr(r, "__dict__") else {"rule_id": r.rule_id, "resource_type": r.resource_type, "action": r.action, "allow_when": r.allow_when} for r in p.rules]} for p in policy_versions],
                   "principals": [p.name for p in principals], "fixtures": sorted(app.state.fixture_refs.get((actor.project_id, payload.target_id), frozenset())),
                   "credentials": "removed by context builder"}
        result = app.state.guidance.suggest_capsules(SuggestRequest(actor.project_id, actor.user_id, payload.target_id,
            payload.operation_ids, context, payload.max_count, payload.policy_version_id))
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="guidance.suggestions_requested", object_ref=str(payload.target_id), payload={"requested_count": payload.max_count, "accepted": result.accepted_count, "rejected": result.rejected_count})
        return result

    @app.get("/v1/suggestions", tags=["guidance"])
    def list_suggestions(request: Request):
        actor = _actor(request)
        return app.state.guidance.list(actor.project_id)

    @app.get("/v1/suggestions/{suggestion_id}", tags=["guidance"])
    def get_suggestion(suggestion_id: UUID, request: Request):
        actor = _actor(request)
        item = app.state.guidance.get(suggestion_id, actor.project_id)
        if item is None:
            raise NotFound("Suggestion not found", code="suggestion.not_found")
        return item

    @app.post("/v1/suggestions/{suggestion_id}/approve", tags=["guidance"])
    def approve_suggestion(suggestion_id: UUID, payload: SuggestionDecisionBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.REVIEWER)
        try:
            item = app.state.guidance.decide(suggestion_id, project_id=actor.project_id, reviewer_id=actor.user_id,
                reviewer_role=CoreRole(actor.role.value), approve=True, comment=payload.comment)
        except (ValueError, CypherError) as exc:
            raise
        except Exception as exc:
            if hasattr(exc, "code"):
                raise
            raise Invalid("Suggestion approval failed", code="suggestion.approval_failed") from exc
        if item.approved_capsule is None:
            raise Invalid("Approved suggestion has no capsule", code="suggestion.payload_missing")
        capsule = app.state.capsules.create(actor.project_id, actor.user_id, item.approved_capsule)
        app.state.capsules.transition(capsule.capsule_version_id, actor.project_id, actor.user_id, CapsuleStatus.VALIDATED)
        app.state.capsules.transition(capsule.capsule_version_id, actor.project_id, actor.user_id, CapsuleStatus.APPROVED)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="guidance.suggestion_approved", object_ref=str(suggestion_id), payload={"capsule_version_id": str(capsule.capsule_version_id), "comment_sha256": sha256_hex(payload.comment.encode("utf-8"))})
        return {"suggestion": item, "capsule_version": capsule, "status": "approved"}

    @app.post("/v1/suggestions/{suggestion_id}/reject", tags=["guidance"])
    def reject_suggestion(suggestion_id: UUID, payload: SuggestionDecisionBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.REVIEWER)
        item = app.state.guidance.decide(suggestion_id, project_id=actor.project_id, reviewer_id=actor.user_id,
            reviewer_role=CoreRole(actor.role.value), approve=False, comment=payload.comment)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="guidance.suggestion_rejected", object_ref=str(suggestion_id), payload={"comment_sha256": sha256_hex(payload.comment.encode("utf-8"))})
        return item

    @app.post("/v1/guidance/explanations", status_code=201, tags=["guidance"])
    def explain_verdict(payload: ExplanationRequestBody, request: Request):
        actor = _actor(request)
        result = app.state.explanation_service.explain_verdict(verdict_id=payload.verdict_id, actor=actor)
        # Memory adapter is dev-only; the record keeps immutable result content and citation IDs.
        app.state.explanations[result.verdict_id] = result
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="guidance.explanation_created", object_ref=str(result.verdict_id), payload={"statement_count": len(result.statements)})
        return result

    @app.post("/v1/history/recommendations", status_code=200, tags=["history"])
    def history_recommendations(payload: HistoryRecommendationBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        result = app.state.history.recommend(project_id=actor.project_id, query=payload.query,
                                             available_evidence_ids=set(payload.available_evidence_ids), limit=payload.limit)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="history.recommendation_drafted", object_ref=str(result.recommendation_id), payload={"state": result.state, "library_size": result.library_size})
        return result

    @app.get("/v1/history/recurrence", tags=["history"])
    def history_recurrence(request: Request):
        actor = _actor(request)
        findings_page = app.state.phase5_services.findings.list(cursor=None, limit=100, actor=actor)
        findings = [{"project_id": str(actor.project_id), "fingerprint": finding.fingerprint} for finding in findings_page.items]
        events: list[dict[str, Any]] = []
        for finding in findings_page.items:
            for event in app.state.phase5_repo.get_finding_timeline(finding.finding_id, actor.project_id):
                events.append({"project_id": str(actor.project_id), "event_type": event.event_type.value,
                               "fingerprint": finding.fingerprint, "operation_id": "unknown", "policy_rule_id": "unknown"})
        return app.state.history.recurrence_report(project_id=actor.project_id, finding_events=tuple(events), findings=tuple(findings))

    @app.post("/v1/history/cases/draft", status_code=201, tags=["history"])
    def draft_history_case(payload: dict[str, Any], request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        required = {"finding_id", "vuln_class", "mutation_dimension", "method", "resource_type", "policy_rule_type", "pattern_summary", "fix_pattern", "evidence_ids", "finding_event_ids"}
        if not required.issubset(payload):
            raise Invalid(f"Missing case fields: {', '.join(sorted(required - set(payload)))}")
        record = app.state.history.draft_case(project_id=actor.project_id, finding_id=UUID(payload["finding_id"]),
            vuln_class=payload["vuln_class"], mutation_dimension=payload["mutation_dimension"], method=payload["method"],
            resource_type=payload["resource_type"], policy_rule_type=payload["policy_rule_type"], pattern_summary=payload["pattern_summary"],
            fix_pattern=payload["fix_pattern"], evidence_ids=tuple(payload["evidence_ids"]), finding_event_ids=tuple(UUID(v) for v in payload["finding_event_ids"]))
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="history.case_drafted", object_ref=str(record.case_id), payload={"finding_id": str(record.finding_id)})
        return record

    @app.post("/v1/history/cases/{case_id}/review", tags=["history"])
    def review_history_case(case_id: UUID, payload: dict[str, Any], request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.REVIEWER)
        from cypher.history.models import OutcomeLabel
        try:
            label = OutcomeLabel(payload.get("label"))
        except (ValueError, TypeError) as exc:
            raise Invalid("Unknown case outcome label") from exc
        record = app.state.history.review_case(case_id=case_id, project_id=actor.project_id, label=label, reviewer_id=actor.user_id,
                                               approve=bool(payload.get("approve", True)), supersedes_case_id=UUID(payload["supersedes_case_id"]) if payload.get("supersedes_case_id") else None)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="history.case_reviewed", object_ref=str(case_id), payload={"label": label.value, "status": record.review_status.value})
        return record

    @app.post("/v1/builds/{build_id}/environments", status_code=201, tags=["sandbox"])
    def create_environment(build_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        build = next((item for target in app.state.targets.list_targets(actor.project_id)
                      for item in app.state.targets.builds_for_target(target.target_id, actor.project_id)
                      if item.build_id == build_id), None)
        if build is None:
            raise NotFound("Build not found", code="build.not_found")
        factory = app.state.environment_factory
        if not callable(factory):
            raise CypherError("Sandbox environment factory is not configured; no environment was created", code="sandbox.not_configured", status_code=503)
        try:
            env = factory(build=build, project_id=actor.project_id, actor_id=actor.user_id)
        except Exception as exc:
            request_logger.exception("sandbox_create_failed", extra={"event": "sandbox_create_failed", "project_id": str(actor.project_id)})
            raise CypherError("Sandbox environment creation failed; see server logs", code="sandbox.create_failed", status_code=503) from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="environment.created", object_ref=str(env.environment_id), payload={"build_id": str(build_id), "image_digest": env.image_digest, "seed_snapshot_hash": env.seed_snapshot_hash})
        return env

    @app.get("/v1/environments/{environment_id}", tags=["sandbox"])
    def get_environment(environment_id: UUID, request: Request):
        actor = _actor(request)
        manager = app.state.environment_manager
        if manager is None or not callable(getattr(manager, "get_environment", None)):
            raise CypherError("Sandbox environment manager is not configured", code="sandbox.not_configured", status_code=503)
        env = manager.get_environment(environment_id, actor.project_id)
        if env is None:
            raise NotFound("Environment not found", code="environment.not_found")
        return env

    @app.post("/v1/environments/{environment_id}/reset", tags=["sandbox"])
    def reset_environment(environment_id: UUID, payload: EnvironmentResetBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        manager = app.state.environment_manager
        if manager is None or not callable(getattr(manager, "get_environment", None)):
            raise CypherError("Sandbox environment manager is not configured", code="sandbox.not_configured", status_code=503)
        env = manager.get_environment(environment_id, actor.project_id)
        if env is None:
            raise NotFound("Environment not found", code="environment.not_found")
        try:
            digest = manager.reset_to_seed(environment_id, payload.seed)
        except Exception as exc:
            request_logger.exception("sandbox_reset_failed", extra={"event": "sandbox_reset_failed", "project_id": str(actor.project_id)})
            raise CypherError("Sandbox reset failed; environment was not certified ready", code="sandbox.reset_failed", status_code=409) from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="environment.reset", object_ref=str(environment_id), payload={"seed": payload.seed, "seed_snapshot_hash": digest})
        return {"environment_id": str(environment_id), "status": "ready", "seed_snapshot_hash": digest}

    @app.delete("/v1/environments/{environment_id}", status_code=204, tags=["sandbox"])
    def destroy_environment(environment_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        manager = app.state.environment_manager
        if manager is None or not callable(getattr(manager, "get_environment", None)):
            raise CypherError("Sandbox environment manager is not configured", code="sandbox.not_configured", status_code=503)
        env = manager.get_environment(environment_id, actor.project_id)
        if env is None:
            raise NotFound("Environment not found", code="environment.not_found")
        try:
            manager.destroy(env)
        except Exception as exc:
            request_logger.exception("sandbox_destroy_failed", extra={"event": "sandbox_destroy_failed", "project_id": str(actor.project_id)})
            raise CypherError("Sandbox environment destruction failed", code="sandbox.destroy_failed", status_code=503) from exc
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="environment.destroyed", object_ref=str(environment_id), payload={"build_id": str(env.build_id)})
        return JSONResponse(status_code=204, content=None)

    @app.post("/v1/replays", status_code=202, tags=["replays"])
    def submit_replay(payload: ReplayRequestBody, request: Request, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN, CoreRole.ANALYST)
        if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 200:
            raise Invalid("A valid Idempotency-Key header is required", code="idempotency.required", status_code=400)
        capsule = app.state.capsules.get(payload.capsule_version_id, actor.project_id)
        if capsule is None:
            raise NotFound("Capsule version not found", code="capsule.not_found")
        if app.state.capsules.status(payload.capsule_version_id) != CapsuleStatus.APPROVED:
            raise Invalid("Only approved capsule versions can be replayed", code="capsule.not_approved")
        target_id = _find_target_for_capsule(app, actor.project_id, capsule.content)
        if target_id is None:
            raise Invalid("Capsule target is missing or ambiguous", code="target.ambiguous")
        for build_id in payload.build_ids:
            build = app.state.targets.get_build(build_id, actor.project_id)
            if build is None or build.target_id != target_id:
                raise NotFound("Build not found for capsule target", code="build.not_found")
        if payload.repeats > app.state.settings.max_repeats:
            raise Invalid("Requested repeats exceed the configured limit", code="replay.repeat_limit")
        submitter = app.state.replay_submitter
        if not callable(submitter):
            raise CypherError("Replay worker is not configured; request was not queued", code="worker.not_configured", status_code=503)
        result = submitter(project_id=actor.project_id, actor_id=actor.user_id, capsule_version_id=payload.capsule_version_id,
                           build_ids=payload.build_ids, repeats=payload.repeats, idempotency_key=idempotency_key)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="replay.submitted", object_ref=str(result.get("job_id", "unknown")),
                               payload={"capsule_version_id": str(payload.capsule_version_id), "build_ids": [str(item) for item in payload.build_ids], "repeats": payload.repeats})
        return result

    @app.get("/v1/replays/{run_id}", tags=["replays"])
    def get_replay(run_id: UUID, request: Request):
        actor = _actor(request)
        run = app.state.phase5_repo.get_run(run_id, actor.project_id)
        if run is None:
            raise NotFound("Replay run not found", code="replay.not_found")
        return run

    @app.get("/v1/replays/{run_id}/evidence", tags=["replays"])
    def get_replay_evidence(run_id: UUID, request: Request):
        actor = _actor(request)
        run = app.state.phase5_repo.get_run(run_id, actor.project_id)
        if run is None:
            raise NotFound("Replay run not found", code="replay.not_found")
        evidence = app.state.phase5_repo.get_evidence_bundle(run_id, actor.project_id)
        if evidence is None:
            raise NotFound("Redacted evidence bundle not found", code="evidence.not_found")
        return evidence

    @app.get("/v1/verdicts/{verdict_id}", tags=["verdicts"])
    def get_verdict(verdict_id: UUID, request: Request):
        actor = _actor(request)
        record = app.state.phase5_repo.get_verdict(verdict_id, actor.project_id)
        if record is None:
            raise NotFound("Verdict not found", code="verdict.not_found")
        return record

    @app.get("/v1/audit", tags=["audit"])
    def get_audit(request: Request, cursor: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500), verify_chain: bool = False):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        all_entries = app.state.audit.entries(actor.project_id)
        selected = [entry for entry in all_entries if entry.seq > cursor][:limit]
        return {"items": selected, "next_cursor": selected[-1].seq if len(selected) == limit else None,
                "chain_valid": app.state.audit.verify(actor.project_id) if verify_chain else None}

    @app.post("/v1/experiments/{experiment_id}/run", status_code=202, tags=["experiments"])
    def run_experiment(experiment_id: UUID, payload: ExperimentRunRequest, request: Request, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        record = app.state.experiments.get(experiment_id)
        if not record or record["project_id"] != actor.project_id:
            raise NotFound("Experiment not found", code="experiment.not_found")
        if not idempotency_key:
            raise Invalid("A valid Idempotency-Key header is required", code="idempotency.required", status_code=400)
        submitter = app.state.experiment_submitter
        if not callable(submitter):
            raise CypherError("Experiment worker is not configured; request was not queued", code="worker.not_configured", status_code=503)
        result = submitter(project_id=actor.project_id, experiment_id=experiment_id, idempotency_key=idempotency_key)
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="experiment.run_submitted", object_ref=str(experiment_id), payload={"idempotency_key_sha256": sha256_hex(idempotency_key.encode("utf-8")), "note_sha256": sha256_hex(payload.note.encode("utf-8"))})
        return result

    @app.get("/v1/experiments/{experiment_id}/results", tags=["experiments"])
    def get_experiment_results(experiment_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        record = app.state.experiments.get(experiment_id)
        if not record or record["project_id"] != actor.project_id:
            raise NotFound("Experiment not found", code="experiment.not_found")
        return {"experiment_id": str(experiment_id), "state": record["state"], "result": record.get("result")}

    @app.post("/v1/experiments", status_code=201, tags=["experiments"])
    def create_experiment(payload: ExperimentCreateBody, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        try:
            config = ExperimentConfig.model_validate(payload.config)
        except Exception as exc:
            raise Invalid("Experiment config is invalid", code="experiment.config_invalid") from exc
        if config.experiment_id in app.state.experiments:
            raise Invalid("Experiment ID already exists", code="experiment.exists", status_code=409)
        app.state.experiments[config.experiment_id] = {"project_id": actor.project_id, "config": config, "state": "configured", "created_by": actor.user_id}
        app.state.audit.append(actor_id=actor.user_id, project_id=actor.project_id, action="experiment.created", object_ref=str(config.experiment_id), payload={"name": config.name, "arms": list(config.arms)})
        return {"experiment_id": str(config.experiment_id), "state": "configured", "config": config}

    @app.get("/v1/experiments/{experiment_id}/export", tags=["experiments"])
    def get_experiment_export(experiment_id: UUID, request: Request):
        actor = _actor(request); require_role(actor.role, CoreRole.ADMIN)
        record = app.state.experiments.get(experiment_id)
        if not record or record["project_id"] != actor.project_id:
            raise NotFound("Experiment not found", code="experiment.not_found")
        return {"experiment_id": str(experiment_id), "state": record["state"], "config": record["config"], "result": record.get("result"), "manifest_hash": record.get("manifest_hash")}

    @app.get("/v1/jobs/{job_id}", tags=["jobs"])
    def get_job(job_id: UUID, request: Request):
        actor = _actor(request)
        dispatcher = app.state.job_dispatcher
        if dispatcher is None:
            raise CypherError("Persistent job storage is not configured", code="worker.not_configured", status_code=503)
        if callable(getattr(dispatcher, "get", None)):
            job = dispatcher.get(job_id, actor.project_id)
        else:
            job = getattr(dispatcher, "jobs", {}).get(job_id)
            if job is not None and getattr(job, "project_id", None) != actor.project_id:
                job = None
        if job is None:
            raise NotFound("Job not found", code="job.not_found")
        return job

    # Phase 5 service APIs are mounted at the official paths. Replay submission remains queued
    # until a real Docker sandbox worker is attached; no pretend verdict is produced here.
    class UnconfiguredReplayRunner:
        def replay(self, *, capsule_version_id: UUID, build_id: UUID, project_id: UUID, repeats: int):
            raise CypherError("Sandbox replay worker is not configured. Configure the Docker environment manager and replay engine before running suites.", code="worker.not_configured", status_code=503)
    services = Phase5Services(app.state.phase5_repo, UnconfiguredReplayRunner(), PureEvidenceAdjudicator())
    app.state.phase5_services = services
    mount_phase5(app, services=services, job_dispatcher=app.state.job_dispatcher)
    # The readiness endpoint is exposed before adding middleware; middleware checks pathname only.
    return app


def _actor(request: Request) -> Actor:
    value = getattr(request.state, "actor", None)
    if not isinstance(value, Actor):
        raise HTTPException(status_code=401, detail="Authentication required")
    return value


def _validation_context(app: FastAPI, project_id: UUID, target_id: UUID | None) -> ValidationContext:
    if target_id is None:
        return ValidationContext(False, frozenset(), frozenset(), frozenset(), frozenset(), frozenset())
    target = app.state.targets.get_target(target_id, project_id)
    operations = app.state.openapi_operations.get((project_id, target_id), {})
    principals = app.state.targets.principals_for_target(target_id, project_id)
    policies = app.state.policies.versions_for(target_id)
    fixtures = app.state.fixture_refs.get((project_id, target_id), frozenset())
    policy_versions = frozenset(p.policy_version_id for p in policies)
    policy_rule_ids = frozenset(rule.rule_id for p in policies for rule in p.rules)
    probe_names = frozenset(app.state.oracle_probes.get((project_id, target_id), {}))
    return ValidationContext(bool(target and target.sandbox_only), frozenset(operations), frozenset(p.name for p in principals),
                             frozenset(fixtures), policy_versions, policy_rule_ids,
                             max_body_bytes=app.state.settings.max_body_bytes,
                             operation_specs=operations, oracle_probe_names=probe_names)


def _find_target_for_capsule(app: FastAPI, project_id: UUID, content: AIC) -> UUID | None:
    # AIC intentionally references operation IDs, not an untrusted network URL. Operations
    # may be registered on multiple targets; fail closed on ambiguity.
    matches: list[UUID] = []
    for (pid, target_id), operations in app.state.openapi_operations.items():
        if pid == project_id and content.target.operation_id in operations and operations[content.target.operation_id] == {"method": content.target.method, "path": content.target.path}:
            matches.append(target_id)
    return matches[0] if len(matches) == 1 else None


def _problem(status_code: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, media_type="application/problem+json", content={
        "type": f"https://cypher.invalid/problems/{code}", "title": code, "status": status_code, "detail": detail, "code": code})


app = create_app()
