"""Local deliberately vulnerable reference API for CYPHER tests only.

Never expose this service outside an isolated sandbox. Tokens and data are fixtures.
"""
from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from threading import RLock
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Cypher Reference Orders API", version="1.0.0")
_VARIANT = os.getenv("CYPHER_VARIANT", "vulnerable")
_LOCK = RLock()
_INITIAL = {
    "order-a1": {"id": "order-a1", "owner_id": "user_a", "customer_email": "alice@example.test", "quantity": 2, "total": 19.5},
    "order-b1": {"id": "order-b1", "owner_id": "user_b", "customer_email": "bob@example.test", "quantity": 5, "total": 48.0},
}
_ORDERS: dict[str, dict[str, Any]] = deepcopy(_INITIAL)


class QuantityPatch(BaseModel):
    quantity: int = Field(ge=1, le=100)


def _principal(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="authentication required")
    token = authorization.removeprefix("Bearer ")
    principals = {"fixture-token-user-a": "user_a", "fixture-token-user-b": "user_b"}
    if token not in principals:
        raise HTTPException(status_code=401, detail="invalid fixture token")
    return principals[token]


def _authorize(principal: str, order: dict[str, Any], operation: str) -> None:
    if _VARIANT == "over_blocking":
        raise HTTPException(status_code=403, detail="all access blocked by test over-blocking variant")
    is_owner = order["owner_id"] == principal
    # partial_fix intentionally secures reads but leaves writes vulnerable.
    fixed_variant = _VARIANT == "fixed" or (_VARIANT == "partial_fix" and operation == "read")
    if fixed_variant and not is_owner:
        raise HTTPException(status_code=404, detail="order not found")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "variant": _VARIANT}


@app.get("/orders/{order_id}", operation_id="getOrder")
def get_order(order_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal = _principal(authorization)
    with _LOCK:
        order = _ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        _authorize(principal, order, "read")
        return dict(order)


@app.patch("/orders/{order_id}", operation_id="updateOrder")
def update_order(order_id: str, patch: QuantityPatch, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    principal = _principal(authorization)
    with _LOCK:
        order = _ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="order not found")
        _authorize(principal, order, "write")
        order["quantity"] = patch.quantity
        order["total"] = round(patch.quantity * (order["total"] / max(1, order["quantity"])), 2)
        return {"id": order["id"], "quantity": order["quantity"]}


@app.post("/internal/reset")
def reset() -> dict[str, Any]:
    """Must only be called from the private worker network; never route externally."""
    with _LOCK:
        _ORDERS.clear()
        _ORDERS.update(deepcopy(_INITIAL))
        ownership = {"user_a": {"order": {"orders.a1": "order-a1"}}, "user_b": {"order": {"orders.a1": "order-b1"}}}
        digest = hashlib.sha256(json.dumps(_ORDERS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"seed_snapshot_hash": digest, "ownership_map": ownership, "order_count": len(_ORDERS)}


@app.get("/internal/state/orders")
def internal_state() -> dict[str, Any]:
    """Oracle fixture for isolated tests only; production oracle connects directly to the DB."""
    with _LOCK:
        return {key: dict(value) for key, value in _ORDERS.items()}
