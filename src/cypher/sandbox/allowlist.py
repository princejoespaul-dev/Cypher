"""Fail-closed URL/host/DNS guard for replay targets."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit
from collections.abc import Callable, Iterable


class ScopeViolation(ValueError):
    """A request would escape its declared sandbox scope."""


@dataclass(frozen=True, slots=True)
class ValidatedDestination:
    scheme: str
    hostname: str
    port: int
    path: str
    resolved_addresses: tuple[str, ...]


def _canonical_host(host: str) -> str:
    host = host.rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeViolation("Invalid internationalized hostname") from exc


def validate_destination(
    url: str,
    *,
    host_allowlist: Iterable[str],
    sandbox_only: bool,
    sandbox_subnets: Iterable[str],
    resolver: Callable[[str, int], Iterable[str]] | None = None,
) -> ValidatedDestination:
    """Validate both hostname and resolved IPs; callers must repeat immediately before send."""
    if not sandbox_only:
        raise ScopeViolation("env.not_sandbox: replay targets must be explicitly sandbox-only")
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname or parts.username or parts.password:
        raise ScopeViolation("scope.invalid_url: only credential-free HTTP URLs inside the sandbox are accepted")
    if parts.fragment or parts.scheme.lower() != parts.scheme:
        raise ScopeViolation("scope.invalid_url: fragments and ambiguous scheme casing are not allowed")
    try:
        port = parts.port or 80
    except ValueError as exc:
        raise ScopeViolation("scope.invalid_port: destination port is invalid") from exc
    host = _canonical_host(parts.hostname)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ScopeViolation("scope.ip_literal_denied: use the registered hostname, not an IP-literal bypass")
    allow = {_canonical_host(item) for item in host_allowlist}
    if host not in allow:
        raise ScopeViolation("scope.host_not_allowed: hostname is not in the target's exact allowlist")
    resolver_fn = resolver or _system_resolver
    resolved = tuple(sorted(set(resolver_fn(host, port))))
    if not resolved:
        raise ScopeViolation("scope.dns_empty: hostname returned no addresses")
    networks = tuple(ipaddress.ip_network(n, strict=False) for n in sandbox_subnets)
    for address in resolved:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ScopeViolation("scope.dns_invalid: resolver returned an invalid address") from exc
        # Prevent mixed-answer rebinding: every returned address must be an approved sandbox IP.
        if not any(ip.version == net.version and ip in net for net in networks):
            raise ScopeViolation("scope.address_not_sandbox: DNS answer is outside configured sandbox subnets")
    return ValidatedDestination(parts.scheme, host, port, parts.path or "/", resolved)


def _system_resolver(host: str, port: int) -> Iterable[str]:
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScopeViolation("scope.dns_failed: destination could not be resolved") from exc
    return {row[4][0] for row in rows}
