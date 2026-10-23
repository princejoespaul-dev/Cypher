# Phase 4 report — Replay harness and deterministic adjudicator

**Status:** Implemented in the reconstructed codebase; integration gate remains partial.

## Built

Added request renderer, allowlist/DNS-validated HTTP executor, address pinning, redaction-first observation/evidence records, replay orchestration, pure ordered verdict rules and repeat/flaky handling.

## Verification

Pure adjudicator, minimality, evidence and scope tests pass.

## Remaining gate

Wire a real Docker environment, credential resolver, registered SQL probes and content-addressed evidence repository into the replay worker; run golden bundles/e2e.

## Decisions / constraints

See ADR 0002, 0003 and `docs/phases/implementation-status.md`. The source attachment contained the plan, not the previous full repository; module and database integration still needs verification against the real project. No measured performance, accuracy, novelty or production-safety claims are made without the planned experiments and infrastructure tests.
