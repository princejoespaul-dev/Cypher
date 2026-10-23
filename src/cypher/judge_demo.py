"""Deterministic, synthetic BOLA scenario used by the one-click judge demo.

This router tests the behavior of a tiny in-process FastAPI target, not canned verdict
flags. The vulnerable and fixed variants share fixtures and differ only in the ownership
check performed by the target endpoint.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, Header, HTTPException
from httpx import ASGITransport, AsyncClient

router = APIRouter(prefix="/v1/judge-demo", tags=["judge-demo"])

ALICE_TOKEN = "judge-demo-alice-only"
BOB_TOKEN = "judge-demo-bob-only"
ALICE_RECORD = "record-alice-001"
BOB_RECORD = "record-bob-001"


def _target_app(*, fixed: bool) -> FastAPI:
    """Build an isolated target with fresh, synthetic records for each test run."""
    target = FastAPI(title="AuthTrace Judge Demo Target")
    records = {
        ALICE_RECORD: {"id": ALICE_RECORD, "owner": "alice", "value": "Alice synthetic report"},
        BOB_RECORD: {"id": BOB_RECORD, "owner": "bob", "value": "Bob synthetic report"},
    }
    tokens = {ALICE_TOKEN: "alice", BOB_TOKEN: "bob"}

    @target.get("/records/{record_id}")
    def read_record(record_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        caller = tokens.get((authorization or "").removeprefix("Bearer "))
        if caller is None:
            raise HTTPException(status_code=401, detail="Synthetic identity required")
        record = records.get(record_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")
        if fixed and record["owner"] != caller:
            raise HTTPException(status_code=403, detail="Record access denied")
        return record

    return target


async def _run_variant(*, fixed: bool) -> dict[str, Any]:
    app = _target_app(fixed=fixed)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://judge-demo.local") as client:
        own = await client.get(f"/records/{ALICE_RECORD}", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
        cross = await client.get(f"/records/{BOB_RECORD}", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
        own_ok = own.status_code == 200 and own.json().get("owner") == "alice"
        cross_denied = cross.status_code in (403, 404) and "value" not in cross.json()
        vulnerable_observed = cross.status_code == 200 and cross.json().get("owner") == "bob"
        expected_vulnerable = not fixed
        cases = [
            {
                "case_id": "BOLA-OWN-READ",
                "actor": "alice",
                "object": "alice-private-record",
                "expected": "ALLOW",
                "observed_status": own.status_code,
                "verdict": "PASS" if own_ok else "FAIL",
                "evidence": "Alice's own synthetic record remains readable" if own_ok else "Owner access unexpectedly failed",
            },
            {
                "case_id": "BOLA-CROSS-USER-READ",
                "actor": "alice",
                "object": "bob-private-record",
                "expected": "DENY",
                "observed_status": cross.status_code,
                "verdict": ("FAIL" if vulnerable_observed else "PASS") if fixed else ("FAIL" if vulnerable_observed else "INCONCLUSIVE"),
                "evidence": (
                    "Cross-user record content was returned to Alice"
                    if vulnerable_observed
                    else "Cross-user request returned no protected record content"
                ),
            },
        ]
        # A fixed target must deny and a vulnerable target must demonstrably leak.
        behavior_matches = (cross_denied and fixed) or (vulnerable_observed and not fixed)
        return {
            "build": "judge-fixed-v1" if fixed else "judge-vulnerable-v1",
            "label": "fixed" if fixed else "vulnerable",
            "cases": cases,
            "behavior": {
                "alice_can_read_own_record": own_ok,
                "alice_can_read_bobs_record": vulnerable_observed,
                "cross_user_status": cross.status_code,
            },
            "scenario_passed": own_ok and behavior_matches and (cases[1]["verdict"] == ("PASS" if fixed else "FAIL")),
        }


@router.get("/scenario")
def scenario() -> dict[str, Any]:
    """Describe the bounded synthetic scenario without exposing real credentials."""
    return {
        "name": "BOLA / IDOR ownership regression",
        "scope": "in-process isolated API; synthetic data only",
        "actors": ["alice", "bob"],
        "records": ["alice-private-record", "bob-private-record"],
        "builds": [
            {"name": "judge-vulnerable-v1", "label": "vulnerable"},
            {"name": "judge-fixed-v1", "label": "fixed"},
        ],
        "note": "The run endpoint executes HTTP requests against fresh target instances; it does not return stored demo verdicts.",
    }


@router.post("/run")
async def run_demo() -> dict[str, Any]:
    """Execute real owner and cross-user HTTP requests against both target variants."""
    vulnerable = await _run_variant(fixed=False)
    fixed = await _run_variant(fixed=True)
    return {
        "scenario": "BOLA / IDOR ownership regression",
        "synthetic_only": True,
        "results": [vulnerable, fixed],
        "summary": {
            "vulnerable_build_detected": vulnerable["scenario_passed"],
            "fixed_build_passed": fixed["scenario_passed"],
            "legitimate_access_preserved": all(item["behavior"]["alice_can_read_own_record"] for item in (vulnerable, fixed)),
            "cross_user_behavior_changed": (
                vulnerable["behavior"]["alice_can_read_bobs_record"]
                and not fixed["behavior"]["alice_can_read_bobs_record"]
            ),
        },
    }
