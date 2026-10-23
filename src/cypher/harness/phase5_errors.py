"""Stable API error contract for Phase 5."""
from __future__ import annotations


class Phase5Error(Exception):
    def __init__(self, code: str, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


class NotFoundError(Phase5Error):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code, detail, 404)


class ForbiddenError(Phase5Error):
    def __init__(self, code: str = "auth.forbidden", detail: str = "Insufficient role for this operation") -> None:
        super().__init__(code, detail, 403)


class ConflictError(Phase5Error):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code, detail, 409)


class ValidationError(Phase5Error):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code, detail, 422)
