from __future__ import annotations

import json
import logging

import pytest

from cypher.core.secrets import EnvironmentSecretsProvider, SecretReferenceError
from cypher.core.structured_logging import JsonLogFormatter


def test_environment_secret_provider_accepts_references_not_values():
    provider = EnvironmentSecretsProvider({"ORDERS_TOKEN": "fixture-secret"})
    assert provider.resolve("env://ORDERS_TOKEN") == "fixture-secret"
    for reference in ("fixture-secret", "env://orders_token", "env://BAD/NAME", "vault://secret"):
        with pytest.raises(SecretReferenceError):
            provider.resolve(reference)


def test_json_log_formatter_keeps_safe_fields_and_omits_unlisted_secret_fields():
    record = logging.LogRecord("cypher.test", logging.INFO, __file__, 1, "request completed", (), None)
    record.event = "http_request"
    record.http_status = 200
    record.authorization = "Bearer must-not-be-logged"
    record.query = "token=must-not-be-logged"
    data = json.loads(JsonLogFormatter().format(record))
    assert data["event"] == "http_request"
    assert data["http_status"] == 200
    assert "authorization" not in data and "query" not in data
    assert "must-not-be-logged" not in json.dumps(data)
