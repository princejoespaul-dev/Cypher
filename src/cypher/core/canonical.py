"""RFC 8785-style canonical JSON for JSON-compatible Cypher records.

Object keys are sorted by UTF-16 code units and finite IEEE-754 numbers use the
ECMAScript/JCS notation thresholds. This keeps hashes stable for the AIC JSON domain;
callers must still only pass JSON values (no custom Python objects).
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _number(value: int | float) -> str:
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise ValueError("JCS forbids NaN and infinity")
    if value == 0:
        return "0"  # JCS normalizes both +0 and -0.
    text = repr(value).lower()
    if "e" not in text:
        if text.endswith(".0"):
            text = text[:-2]
        return text
    mantissa, exponent_text = text.split("e", 1)
    exponent = int(exponent_text)
    sign = ""
    if mantissa.startswith("-"):
        sign, mantissa = "-", mantissa[1:]
    digits = mantissa.replace(".", "")
    decimal_pos = (mantissa.find(".") if "." in mantissa else len(mantissa)) + exponent
    # ECMAScript uses decimal notation for exponents in [-6, 20].
    if -6 <= exponent < 21:
        if decimal_pos <= 0:
            return sign + "0." + ("0" * (-decimal_pos)) + digits
        if decimal_pos >= len(digits):
            return sign + digits + ("0" * (decimal_pos - len(digits)))
        return sign + digits[:decimal_pos] + "." + digits[decimal_pos:]
    # Outside that interval, normalize the exponent and omit leading zeroes.
    rest = digits[1:]
    mant = digits[0] + ("." + rest if rest else "")
    exp_out = decimal_pos - 1
    return f"{sign}{mant}e{'+' if exp_out >= 0 else ''}{exp_out}"


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return _number(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", errors="surrogatepass"))
        return "{" + ",".join(_serialize(key) + ":" + _serialize(value[key]) for key in keys) + "}"
    raise TypeError(f"Unsupported canonical JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any, *, permit_float: bool = True) -> bytes:
    """Serialize JSON data into deterministic JCS-compatible bytes."""
    # permit_float is retained as a compatibility argument for earlier callers.
    if not permit_float:
        def check(item: Any, path: str = "$") -> None:
            if isinstance(item, float):
                raise TypeError(f"Floating-point values are not allowed at {path}")
            if isinstance(item, dict):
                for key, nested in item.items():
                    check(nested, f"{path}.{key}")
            elif isinstance(item, (list, tuple)):
                for index, nested in enumerate(item):
                    check(nested, f"{path}[{index}]")
        check(value)
    return _serialize(value).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def content_hash(value: Any) -> str:
    return sha256_hex(canonical_json_bytes(value))
