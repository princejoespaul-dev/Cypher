# Phase 5 report — Findings, fix verification and recurrence

**Status:** Phase 5 service logic is implemented and covered by unit tests; the database-backed release gate is not complete.

## Built

- Findings are keyed by the capsule fingerprint and emit append-only `open`, `fixed_verified` and `reintroduced` events.
- Fix verification classifies stored vulnerable/fixed-build evidence as `FIX_VERIFIED`, `FIX_INCOMPLETE`, `FIX_BREAKS_CONTROL` or `FIX_UNVERIFIABLE`. A failed positive control is not interpreted as a security pass.
- Regression suite runs return the boolean `failed` gate when a finding whose fix was previously verified becomes vulnerable again.
- Re-adjudication uses stored evidence and a selected pure adjudicator version, appending a new verdict row instead of changing the previous row.
- Phase 5 routes are mounted from the main FastAPI app; long-running submission remains queued only when a real dispatcher is injected.

## Verification

The Phase 5-specific test file and shared unit suite pass in this environment; the full reconstructed project has **57 passing tests**.

## Remaining gate

Run Phase 5 migrations on a clean PostgreSQL instance and verify append-only event triggers/RLS; then execute vulnerable → fixed → reintroduced plus partial-fix and over-blocking scenarios against the public API and actual Docker worker. The earlier repository was not provided, so the reconstructed migration parent must be compared to the actual schema before merge.

## ADR

See `docs/adr/0005-phase5-outcome-and-recurrence-rules.md`.
