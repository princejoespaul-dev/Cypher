"""Redact credentials and token-like values before any evidence write or model call."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_SENSITIVE_KEYS = re.compile(r"(?i)(authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|session[_-]?token)")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


@dataclass(frozen=True, slots=True)
class RedactionReport:
    fields_redacted: int
    patterns_redacted: int
    paths: tuple[str, ...]


def redact_value(value: Any) -> tuple[Any, RedactionReport]:
    paths: list[str] = []
    patterns = 0

    def walk(item: Any, path: str = "$") -> Any:
        nonlocal patterns
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for key, nested in item.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}"
                if _SENSITIVE_KEYS.search(key_text):
                    paths.append(child_path)
                    result[key_text] = "[REDACTED]"
                else:
                    result[key_text] = walk(nested, child_path)
            return result
        if isinstance(item, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(item)]
        if isinstance(item, str):
            updated, count1 = _BEARER.subn("Bearer [REDACTED]", item)
            updated, count2 = _JWT.subn("[REDACTED_JWT]", updated)
            patterns += count1 + count2
            return updated
        return item

    redacted = walk(value)
    return redacted, RedactionReport(len(paths), patterns, tuple(paths))


def redact_headers(headers: dict[str, str]) -> tuple[dict[str, str], RedactionReport]:
    return redact_value(headers)


def redact_json_text(text: str, *, max_bytes: int = 1_048_576) -> tuple[str, RedactionReport]:
    encoded = text.encode("utf-8", errors="replace")[:max_bytes]
    clipped = encoded.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(clipped)
    except json.JSONDecodeError:
        redacted, patterns = _BEARER.subn("Bearer [REDACTED]", clipped)
        redacted, count2 = _JWT.subn("[REDACTED_JWT]", redacted)
        return redacted, RedactionReport(0, patterns + count2, ())
    safe, report = redact_value(parsed)
    return json.dumps(safe, ensure_ascii=False, separators=(",", ":")), report
