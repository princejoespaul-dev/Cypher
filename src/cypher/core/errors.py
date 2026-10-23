"""Stable domain errors mapped to RFC 9457 problem details by the API."""
from __future__ import annotations


class CypherError(Exception):
    status_code = 400
    code = "cypher.error"

    def __init__(self, detail: str, *, code: str | None = None, status_code: int | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code


class Unauthorized(CypherError):
    status_code = 401
    code = "auth.invalid_key"


class Forbidden(CypherError):
    status_code = 403
    code = "auth.forbidden"


class NotFound(CypherError):
    status_code = 404
    code = "resource.not_found"


class Conflict(CypherError):
    status_code = 409
    code = "resource.conflict"


class Invalid(CypherError):
    status_code = 422
    code = "request.invalid"
