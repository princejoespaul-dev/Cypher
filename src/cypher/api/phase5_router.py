"""FastAPI router for Phase 5 endpoints.

Integration contract: the main app must set ``app.state.phase5_services`` and
``app.state.phase5_job_dispatcher``. Existing authentication middleware must set
``request.state.actor`` to a mapping/object exposing user_id, project_id, and role.
"""
from __future__ import annotations

from typing import Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from cypher.harness.phase5_errors import Phase5Error
from cypher.harness.phase5_models import (
    Actor,
    FindingEventRecord,
    FindingPage,
    FixVerificationRecord,
    FixVerificationRequest,
    ReadjudicateRequest,
    RegressionSuiteCreate,
    RegressionSuiteRecord,
    RegressionSuiteRunRequest,
    StoredVerdictRecord,
)
from cypher.harness.phase5_service import Phase5Services


class JobAccepted(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: UUID
    state: str = "queued"
    status_url: str


class SuiteJobDispatcher(Protocol):
    """Adapter to the Phase 0 queue/worker infrastructure (Arq, Dramatiq, etc.)."""

    def enqueue_regression_suite(
        self,
        *,
        suite_id: UUID,
        build_id: UUID,
        repeats: int,
        actor: Actor,
        idempotency_key: str,
    ) -> UUID: ...


router = APIRouter(prefix="/v1", tags=["phase-5-findings-fix-verification"])


def get_services(request: Request) -> Phase5Services:
    services = getattr(request.app.state, "phase5_services", None)
    if not isinstance(services, Phase5Services):
        raise RuntimeError("app.state.phase5_services is not configured")
    return services


def get_actor(request: Request) -> Actor:
    raw = getattr(request.state, "actor", None)
    if raw is None:
        raise HTTPException(status_code=401, detail={"code": "auth.required", "detail": "Authentication required"})
    if isinstance(raw, Actor):
        return raw
    if isinstance(raw, dict):
        values = raw
    else:
        values = {
            "user_id": getattr(raw, "user_id", None),
            "project_id": getattr(raw, "project_id", None),
            "role": getattr(raw, "role", None),
        }
    try:
        return Actor.model_validate(values)
    except Exception as exc:
        raise HTTPException(status_code=401, detail={"code": "auth.invalid_context", "detail": "Authentication context is invalid"}) from exc


def install_phase5_exception_handler(app: FastAPI) -> None:
    def problem(status_code: int, code: str, detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            media_type="application/problem+json",
            content={
                "type": f"https://cypher.invalid/problems/{code}",
                "title": code,
                "status": status_code,
                "detail": detail,
                "code": code,
            },
        )

    @app.exception_handler(Phase5Error)
    async def _phase5_error_handler(_request: Request, exc: Phase5Error) -> JSONResponse:
        return problem(exc.status_code, exc.code, exc.detail)

    @app.exception_handler(HTTPException)
    async def _http_error_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = str(detail.get("code", "http.error"))
            message = str(detail.get("detail", "Request failed"))
        else:
            code, message = "http.error", str(detail)
        return problem(exc.status_code, code, message)

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not echo submitted values; malformed payloads can contain tokens/secrets.
        fields = [".".join(str(part) for part in error.get("loc", ())) for error in exc.errors()]
        detail = "Request validation failed" + (f" for: {', '.join(fields[:12])}" if fields else "")
        return problem(422, "request.invalid", detail)


def mount_phase5(app: FastAPI, *, services: Phase5Services, job_dispatcher: SuiteJobDispatcher) -> None:
    """Mount the router and install RFC 9457 problem responses on the main FastAPI app."""
    app.state.phase5_services = services
    app.state.phase5_repository = services.repository
    app.state.phase5_job_dispatcher = job_dispatcher
    app.include_router(router)
    install_phase5_exception_handler(app)


@router.post("/fix-verifications", status_code=status.HTTP_201_CREATED, response_model=FixVerificationRecord)
def verify_fix(
    payload: FixVerificationRequest,
    actor: Actor = Depends(get_actor),
    services: Phase5Services = Depends(get_services),
) -> FixVerificationRecord:
    return services.fix_verification.verify(
        vulnerable_run_id=payload.vulnerable_run_id,
        fixed_run_id=payload.fixed_run_id,
        actor=actor,
    )


@router.post("/regression-suites", status_code=status.HTTP_201_CREATED, response_model=RegressionSuiteRecord)
def create_regression_suite(
    payload: RegressionSuiteCreate,
    actor: Actor = Depends(get_actor),
    services: Phase5Services = Depends(get_services),
) -> RegressionSuiteRecord:
    return services.regression_suites.create(payload, actor)


@router.post("/regression-suites/{suite_id}/run", status_code=status.HTTP_202_ACCEPTED, response_model=JobAccepted)
def run_regression_suite(
    suite_id: UUID,
    payload: RegressionSuiteRunRequest,
    request: Request,
    actor: Actor = Depends(get_actor),
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=128),
) -> JobAccepted:
    dispatcher = getattr(request.app.state, "phase5_job_dispatcher", None)
    settings = getattr(request.app.state, "settings", None)
    if settings is not None and payload.repeats > settings.max_repeats:
        raise HTTPException(status_code=422, detail={"code": "replay.repeat_limit", "detail": "Requested repeats exceed the configured limit"})
    if dispatcher is None:
        raise HTTPException(status_code=503, detail={"code": "worker.not_configured", "detail": "Persistent job dispatcher is not configured"})
    job_id = dispatcher.enqueue_regression_suite(
        suite_id=suite_id,
        build_id=payload.build_id,
        repeats=payload.repeats,
        actor=actor,
        idempotency_key=idempotency_key,
    )
    return JobAccepted(job_id=job_id, status_url=f"/v1/jobs/{job_id}")


@router.get("/findings", response_model=FindingPage)
def list_findings(
    cursor: UUID | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    actor: Actor = Depends(get_actor),
    services: Phase5Services = Depends(get_services),
) -> FindingPage:
    return services.findings.list(cursor=cursor, limit=limit, actor=actor)


class FindingTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: UUID
    events: tuple[FindingEventRecord, ...]


@router.get("/findings/{finding_id}/timeline", response_model=FindingTimelineResponse)
def finding_timeline(
    finding_id: UUID,
    actor: Actor = Depends(get_actor),
    services: Phase5Services = Depends(get_services),
) -> FindingTimelineResponse:
    return FindingTimelineResponse(finding_id=finding_id, events=services.findings.timeline(finding_id=finding_id, actor=actor))


@router.post("/verdicts/{verdict_id}/readjudicate", status_code=status.HTTP_201_CREATED, response_model=StoredVerdictRecord)
def readjudicate_verdict(
    verdict_id: UUID,
    payload: ReadjudicateRequest,
    actor: Actor = Depends(get_actor),
    services: Phase5Services = Depends(get_services),
) -> StoredVerdictRecord:
    return services.readjudication.run(verdict_id=verdict_id, request=payload, actor=actor)
