from __future__ import annotations

from uuid import uuid4

import pytest

from cypher.capsules.models import AIC


@pytest.fixture
def policy_id():
    return uuid4()


@pytest.fixture
def valid_aic(policy_id) -> AIC:
    return AIC.model_validate({
        "aic_version": "1.0",
        "title": "Only the owner may read an order",
        "vuln_class": "BOLA",
        "target": {"operation_id": "getOrder", "method": "GET", "path": "/orders/{order_id}"},
        "policy": {"policy_version_id": str(policy_id), "rule_id": "orders.read.owner_only"},
        "principals": {"owner": "user_a", "other": "user_b"},
        "resource": {"type": "order", "fixture_ref": "orders.a1"},
        "positive_control": {"as": "user_a", "request": {"path_params": {"order_id": "$resource.id"}},
                              "expect": {"status_in": [200], "fingerprint_fields": ["$.id", "$.customer_email"]}},
        "counterfactual": {"mutation": {"dimension": "principal", "from": "user_a", "to": "user_b"},
                           "expect_denied": {"status_in": [401, 403, 404], "leak_check": "fingerprint_absent"}},
        "state_oracle": {"enabled": True, "probes": ["orders_row_hash"], "expect": "unchanged"},
        "safety": {"sandbox_only": True, "destructive": False},
        "provenance": {"authored_by": "human", "suggestion_id": None},
    })
