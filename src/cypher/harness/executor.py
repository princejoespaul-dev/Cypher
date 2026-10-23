"""HTTP executor that rechecks DNS, forbids redirects and redacts evidence before return."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from time import perf_counter
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from collections.abc import Callable, Iterable

import httpx

from cypher.evidence.redaction import redact_headers, redact_json_text, redact_value
from cypher.sandbox.allowlist import ScopeViolation, validate_destination
from cypher.harness.renderer import RenderedRequest


@dataclass(frozen=True, slots=True)
class HttpObservation:
    step: str
    request: dict[str, Any]
    status_code: int | None
    response_headers: dict[str, str]
    body_json: Any | None
    body_text: str
    response_sha256: str | None
    latency_ms: float | None
    error: str | None
    redaction_report: dict[str, Any]


class SafeHttpExecutor:
    def __init__(self, *, timeout_seconds: float = 8.0, max_body_bytes: int = 1_048_576,
                 sandbox_subnets: tuple[str, ...] = ("172.28.0.0/16",), client: httpx.Client | None = None,
                 resolver: Callable[[str, int], Iterable[str]] | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_body_bytes = max_body_bytes
        self.sandbox_subnets = sandbox_subnets
        self._client = client
        self._resolver = resolver

    def preflight(self, *, base_url: str, allowlist: tuple[str, ...], sandbox_only: bool) -> None:
        """Resolve and validate the registered target before the sandbox reset begins."""
        validate_destination(base_url, host_allowlist=allowlist, sandbox_only=sandbox_only,
                             sandbox_subnets=self.sandbox_subnets, resolver=self._resolver)

    def send(self, *, base_url: str, allowlist: tuple[str, ...], sandbox_only: bool, request: RenderedRequest, bearer_token: str | None, step: str) -> HttpObservation:
        url = urljoin(base_url.rstrip("/") + "/", request.path.lstrip("/"))
        if request.query_params:
            url = url + ("&" if "?" in url else "?") + urlencode(request.query_params, doseq=True)
        destination = validate_destination(url, host_allowlist=allowlist, sandbox_only=sandbox_only,
                                            sandbox_subnets=self.sandbox_subnets, resolver=self._resolver)
        # Pin the TCP destination to the address that passed the allowlist/subnet check. Sending
        # the original hostname to HTTPX would trigger another DNS lookup and reopen a rebinding race.
        ip = destination.resolved_addresses[0]
        pinned_host = f"[{ip}]" if ":" in ip else ip
        parsed_url = urlsplit(url)
        pinned_netloc = f"{pinned_host}:{destination.port}"
        pinned_url = urlunsplit((destination.scheme, pinned_netloc, parsed_url.path or "/", parsed_url.query, ""))
        headers = {"Accept": "application/json", "Host": destination.hostname if destination.port == 80 else f"{destination.hostname}:{destination.port}"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        safe_headers, header_report = redact_headers(headers)
        safe_request_body, request_body_report = redact_value(request.body)
        request_evidence = {"method": request.method, "url": f"{destination.scheme}://{destination.hostname}:{destination.port}{destination.path}",
                            "headers": safe_headers, "body": safe_request_body}
        started = perf_counter()
        try:
            client = self._client or httpx.Client(timeout=self.timeout_seconds, follow_redirects=False, trust_env=False)
            response = client.request(request.method, pinned_url, headers=headers, json=request.body, follow_redirects=False)
            elapsed = round((perf_counter() - started) * 1000, 3)
            if 300 <= response.status_code < 400:
                return HttpObservation(step, request_evidence, response.status_code, {}, None, "", None, elapsed,
                                       "redirect_refused", {"header": asdict(header_report)})
            raw = response.content[:self.max_body_bytes]
            decoded = raw.decode(response.encoding or "utf-8", errors="replace")
            redacted_text, body_report = redact_json_text(decoded, max_bytes=self.max_body_bytes)
            try:
                body_json = json.loads(redacted_text)
            except json.JSONDecodeError:
                body_json = None
            safe_response_headers, response_header_report = redact_headers(dict(response.headers))
            digest = hashlib.sha256(redacted_text.encode("utf-8")).hexdigest()
            report = {"request_header_fields": header_report.fields_redacted, "request_body_fields": request_body_report.fields_redacted,
                      "request_body_patterns": request_body_report.patterns_redacted,
                      "response_header_fields": response_header_report.fields_redacted,
                      "body_fields": body_report.fields_redacted, "body_patterns": body_report.patterns_redacted,
                      "body_paths": list(body_report.paths)}
            return HttpObservation(step, request_evidence, response.status_code, safe_response_headers, body_json,
                                   redacted_text, digest, elapsed, None, report)
        except (httpx.HTTPError, ScopeViolation, OSError, ValueError) as exc:
            elapsed = round((perf_counter() - started) * 1000, 3)
            return HttpObservation(step, request_evidence, None, {}, None, "", None, elapsed,
                                   type(exc).__name__, {"request_header_fields": header_report.fields_redacted})
        finally:
            if self._client is None:
                try:
                    client.close()
                except UnboundLocalError:
                    pass
