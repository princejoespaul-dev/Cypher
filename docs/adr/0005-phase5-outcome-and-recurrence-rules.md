# ADR-0005: Phase 5 fix-verification precedence and recurrence state

**Status:** Proposed pending integration tests against the existing Phase 0–4 repository.

## Context

The plan has overlapping descriptions: `FIX_UNVERIFIABLE` covers inconclusive runs, while `FIX_BREAKS_CONTROL` is specifically the condition where the fixed candidate blocks legitimate owner access. The required gates also name `partial_fix` and `over_blocking` build variants, although they are not both labelled `fixed`.

## Decisions

1. A fix pair is considered only when it targets the same target and capsule fingerprint, the first run uses a `vulnerable` build, both runs use the exact same immutable capsule version, both runs are finished and sandbox-only, and the candidate build is labelled `fixed`, `partial_fix`, or `over_blocking`.
2. The vulnerable build must first produce a non-inconclusive `VULNERABLE_*` verdict with `control_ok=true`; otherwise the outcome is `FIX_UNVERIFIABLE`.
3. An environment failure or flaky result on the candidate build is `FIX_UNVERIFIABLE`. If the vulnerable build reproduced the issue and the candidate's owner control is explicitly `false` without an environment error, use `FIX_BREAKS_CONTROL`. This resolves the over-blocking/inconclusive-control overlap in favour of the explicit Phase 5 gate.
4. A candidate that remains `VULNERABLE_*` produces `FIX_INCOMPLETE`. Only a build labelled `fixed` can produce `FIX_VERIFIED`; a protected result from a `partial_fix`/`over_blocking` build is not promoted to a general fix claim.
5. Finding identity is `(project_id, fingerprint)`. `open` is appended once at first vulnerable observation. `fixed_verified` is appended for each valid fix-verification record. If the latest event is `fixed_verified`, a vulnerable suite run appends `reintroduced` and fails that suite run. While the current event is `reintroduced`, subsequent vulnerable suite runs continue to fail the CI gate without duplicating the event; a later verified fix appends `fixed_verified` and re-arms recurrence detection.
6. Re-adjudication is strictly append-only. New verdicts reference the old row with `supersedes_verdict_id`; history is never rewritten.
7. The audit-chain adapter maintains a project-local chain because access to `audit_log` is row-level-security scoped by project. If the core Phase 1 implementation establishes a global chain via a trusted database function, use that existing writer instead of the reference appender.

## Consequences

These decisions are deterministic and unit-tested. They must be checked against the existing adjudicator signals and actual table contracts before the database migration is applied. No LLM participates in classification, finding state transitions, or recurrence calculations.
