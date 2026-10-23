"""Acceptance tests for the isolated one-click BOLA judge demo."""
from __future__ import annotations

import asyncio

from cypher.judge_demo import _run_variant


def test_vulnerable_variant_exposes_cross_user_record_and_preserves_own_access() -> None:
    result = asyncio.run(_run_variant(fixed=False))
    assert result["scenario_passed"] is True
    assert result["behavior"]["alice_can_read_own_record"] is True
    assert result["behavior"]["alice_can_read_bobs_record"] is True
    assert result["cases"][1]["verdict"] == "FAIL"


def test_fixed_variant_denies_cross_user_record_and_preserves_own_access() -> None:
    result = asyncio.run(_run_variant(fixed=True))
    assert result["scenario_passed"] is True
    assert result["behavior"]["alice_can_read_own_record"] is True
    assert result["behavior"]["alice_can_read_bobs_record"] is False
    assert result["behavior"]["cross_user_status"] in (403, 404)
    assert result["cases"][1]["verdict"] == "PASS"
