# Phase 3 report — Sandbox, targets and builds

**Status:** Implemented in the reconstructed codebase; integration gate remains partial.

## Built

Added target/build metadata, immutable image digest validation, reference Orders API with vulnerable/fixed/partial-fix/over-blocking/reintroduced variants, sandbox lifecycle ports, address allowlist checks and read-only oracle interfaces.

## Verification

Scope and SQL-probe security tests pass.

## Remaining gate

Run every Docker variant in a private network, prove no external egress, measure repeatable seed/reset, and verify read-only DB privileges live.

## Decisions / constraints

See ADR 0003 and `docs/phases/implementation-status.md`. The source attachment contained the plan, not the previous full repository; module and database integration still needs verification against the real project. No measured performance, accuracy, novelty or production-safety claims are made without the planned experiments and infrastructure tests.
