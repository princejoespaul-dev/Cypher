"""Deterministic benchmark metric definitions over stored verdicts and ground truth."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from cypher.harness.phase5_models import Verdict


@dataclass(frozen=True, slots=True)
class VerdictSample:
    pair_id: str
    ground_truth_vulnerable: bool
    verdict: Verdict
    build_is_fixed: bool


def calculate_verdict_metrics(samples: Iterable[VerdictSample]) -> dict[str, float | int | None]:
    rows = tuple(samples)
    decisive = [r for r in rows if not r.verdict.is_inconclusive]
    tp = sum(r.ground_truth_vulnerable and r.verdict.is_vulnerable for r in decisive)
    fp = sum((not r.ground_truth_vulnerable) and r.verdict.is_vulnerable for r in decisive)
    fn = sum(r.ground_truth_vulnerable and r.verdict == Verdict.PROTECTED for r in decisive)
    tn = sum((not r.ground_truth_vulnerable) and r.verdict == Verdict.PROTECTED for r in decisive)
    actual_positive = tp + fn
    predicted_positive = tp + fp
    fixed_truth = [r for r in rows if r.build_is_fixed]
    false_positives_fixed = sum(r.verdict.is_vulnerable for r in fixed_truth)
    abstentions = sum(r.verdict.is_inconclusive for r in rows)
    return {
        "sample_count": len(rows), "decisive_count": len(decisive), "true_positive": tp, "false_positive": fp,
        "false_negative": fn, "true_negative": tn,
        "precision": tp / predicted_positive if predicted_positive else None,
        "recall": tp / actual_positive if actual_positive else None,
        "false_positive_rate_fixed": false_positives_fixed / len(fixed_truth) if fixed_truth else None,
        "abstention_rate": abstentions / len(rows) if rows else None,
    }


def fix_verification_accuracy(expected: dict[str, str], observed: dict[str, str]) -> float | None:
    if not expected:
        return None
    return sum(observed.get(key) == value for key, value in expected.items()) / len(expected)


def recurrence_recall(expected_reintroductions: set[str], detected_fingerprints: set[str]) -> float | None:
    if not expected_reintroductions:
        return None
    return len(expected_reintroductions & detected_fingerprints) / len(expected_reintroductions)
