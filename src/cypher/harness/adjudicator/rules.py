"""Pure versioned adjudication rules. No I/O, clock, random, environment or network access."""
from __future__ import annotations

from typing import Any

from cypher.harness.phase5_models import AdjudicationDecision, EvidenceBundle, Verdict

DEFAULT_ADJUDICATOR_VERSION = "1.0.0"


def _jsonpath(value: Any, expression: str) -> Any:
    """Small deterministic JSONPath subset: $.key[0].nested; unsupported syntax yields None."""
    if not expression.startswith("$"):
        return None
    current = value
    for part in expression[1:].strip(".").replace("[", ".").replace("]", "").split("."):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def extract_signals(evidence: EvidenceBundle) -> dict[str, bool | None]:
    """Derive adjudication signals only from stored evidence fields."""
    obs = {str(row.get("step")): row for row in evidence.observations}
    positive = obs.get("positive_control", {})
    counter = obs.get("counterfactual", {})
    expected = evidence.capsule.get("counterfactual", {})
    expect_denied = expected.get("expect_denied", {}) if isinstance(expected, dict) else {}
    statuses = expect_denied.get("status_in", []) if isinstance(expect_denied, dict) else []
    status_code = counter.get("status_code")
    counter_body = counter.get("body_json", counter.get("body_text", ""))
    pos_body = positive.get("body_json", {})
    fingerprint_fields: list[str] = []
    pc = evidence.capsule.get("positive_control", {})
    if isinstance(pc, dict):
        exp = pc.get("expect", {})
        if isinstance(exp, dict):
            fingerprint_fields = [str(v) for v in exp.get("fingerprint_fields", [])]
    leaked = False
    for expression in fingerprint_fields:
        secret_value = _jsonpath(pos_body, expression)
        if secret_value is not None and secret_value != "" and _contains(counter_body, secret_value):
            leaked = True
            break
    error_observations = [row for row in (positive, counter) if row.get("error") or row.get("transport_error")]
    server_errors = any(isinstance(row.get("status_code"), int) and int(row["status_code"]) >= 500 for row in (positive, counter))
    owner_login_failed = bool(positive.get("owner_login_failed"))
    env_error = bool(error_observations) or server_errors or owner_login_failed
    positive_expected = pc.get("expect", {}).get("status_in", []) if isinstance(pc, dict) and isinstance(pc.get("expect", {}), dict) else []
    control_ok = not env_error and positive.get("status_code") in positive_expected
    cf_denied: bool | None = None
    if isinstance(statuses, list) and status_code is not None:
        cf_denied = status_code in statuses
    leak_signal: bool | None = leaked if fingerprint_fields else None
    state_changed: bool | None = None
    oracle = evidence.capsule.get("state_oracle", {})
    if isinstance(oracle, dict) and oracle.get("enabled"):
        snapshots = {(str(row.get("phase")), str(row.get("probe_name"))): row for row in evidence.state_snapshots}
        probe_names = [str(v) for v in oracle.get("probes", [])]
        if probe_names:
            pre_values = [snapshots.get(("pre", name), {}).get("result_sha256") for name in probe_names]
            post_values = [snapshots.get(("post", name), {}).get("result_sha256") for name in probe_names]
            if all(value is not None for value in pre_values + post_values):
                state_changed = pre_values != post_values
    return {
        "env_error": env_error,
        "control_ok": control_ok,
        "cf_denied": cf_denied,
        "cf_leak": leak_signal,
        "state_changed": state_changed,
    }


def _contains(haystack: Any, needle: Any) -> bool:
    """Value equality in decoded JSON, or conservative string containment in text."""
    if isinstance(haystack, (dict, list)):
        if haystack == needle:
            return True
        if isinstance(haystack, dict):
            return any(_contains(value, needle) for value in haystack.values())
        return any(_contains(value, needle) for value in haystack)
    if isinstance(haystack, str):
        if isinstance(needle, (dict, list)):
            return False
        return str(needle) in haystack
    return haystack == needle


def completeness_score(evidence: EvidenceBundle) -> float:
    """Version-1 fixed weighted evidence checklist; missing items contribute zero."""
    capsule = evidence.capsule
    observations = {str(o.get("step")): o for o in evidence.observations}
    positive = observations.get("positive_control", {})
    counter = observations.get("counterfactual", {})
    oracle = capsule.get("state_oracle", {})
    checklist: list[tuple[int, bool]] = [
        (1, bool(positive.get("request") and positive.get("status_code") is not None)),
        (1, bool(positive.get("response_sha256"))),
        (1, bool(counter.get("request") and counter.get("status_code") is not None)),
        (1, bool(counter.get("response_sha256"))),
        (1, bool(capsule.get("policy"))),
        (2, bool(capsule.get("content_hash"))),
        (2, bool(capsule.get("build_image_digest"))),
        (1, bool(capsule.get("seed_snapshot_hash"))),
        (1, bool(capsule.get("harness_version"))),
        (1, bool(capsule.get("adjudicator_version"))),
        (1, bool(capsule.get("redaction_report"))),
    ]
    if isinstance(oracle, dict) and oracle.get("enabled"):
        checklist.extend([
            (1, any(s.get("phase") == "pre" for s in evidence.state_snapshots)),
            (1, any(s.get("phase") == "post" for s in evidence.state_snapshots)),
        ])
    weight = sum(item[0] for item in checklist)
    present = sum(item[0] for item in checklist if item[1])
    return present / weight if weight else 0.0


def adjudicate(evidence: EvidenceBundle, *, adjudicator_version: str = DEFAULT_ADJUDICATOR_VERSION) -> AdjudicationDecision:
    """Pure first-match rule engine as specified in Backend Plan.md."""
    signals = extract_signals(evidence)
    if signals["env_error"]:
        verdict, rule = Verdict.INCONCLUSIVE_ENVIRONMENT, "R1_ENV_ERROR"
    elif not signals["control_ok"]:
        verdict, rule = Verdict.INCONCLUSIVE_CONTROL, "R2_CONTROL_FAILED"
    elif signals["state_changed"] is True:
        verdict, rule = Verdict.VULNERABLE_STATE_CHANGE, "R3_STATE_CHANGED"
    elif signals["cf_leak"] is True:
        verdict, rule = Verdict.VULNERABLE_DATA_EXPOSURE, "R4_DATA_LEAK"
    elif signals["cf_denied"] is True and signals["cf_leak"] is not True and signals["state_changed"] is not True:
        verdict, rule = Verdict.PROTECTED, "R5_DENIED_NO_SIDE_EFFECT"
    else:
        verdict, rule = Verdict.INCONCLUSIVE_AMBIGUOUS, "R6_AMBIGUOUS"
    return AdjudicationDecision(verdict=verdict, fired_rules=(rule,), signals=signals,
                                completeness_score=completeness_score(evidence), adjudicator_version=adjudicator_version)


class PureEvidenceAdjudicator:
    """Adapter expected by Phase 5 re-adjudication."""
    def adjudicate(self, *, evidence: EvidenceBundle, adjudicator_version: str) -> AdjudicationDecision:
        return adjudicate(evidence, adjudicator_version=adjudicator_version)
