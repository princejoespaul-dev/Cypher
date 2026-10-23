"""Minimal secret-reference interface with a fail-closed environment implementation.

References, never secret values, belong in capsule/target metadata. A production secret
manager adapter should implement the same protocol and enforce workload identity/rotation.
"""
from __future__ import annotations

import os
import re
from typing import Protocol, runtime_checkable


class SecretReferenceError(ValueError):
    """Raised when a secret reference is malformed or cannot be resolved."""


@runtime_checkable
class SecretsProvider(Protocol):
    def resolve(self, reference: str) -> str: ...


class EnvironmentSecretsProvider:
    """Resolve only explicit ``env://VARIABLE_NAME`` references; never echo values in errors."""

    _VALID_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = os.environ if environ is None else environ

    def resolve(self, reference: str) -> str:
        if not isinstance(reference, str) or not reference.startswith("env://"):
            raise SecretReferenceError("Secret references must use env://NAME syntax")
        name = reference.removeprefix("env://")
        if not self._VALID_NAME.fullmatch(name):
            raise SecretReferenceError("Secret reference contains an invalid variable name")
        value = self._environ.get(name)
        if not value:
            raise SecretReferenceError("The referenced secret is not configured")
        return value
