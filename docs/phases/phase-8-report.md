# Phase 8 report — Cyphrus historical analysis

**Status:** Implemented in the reconstructed codebase; integration gate remains partial.

## Built

Added case draft/review workflow, frozen reviewed cases with successor correction, filter + keyword retrieval abstraction, citation checks, recommendation validation and deterministic recurrence analytics.

## Verification

Case visibility, immutability and invented-citation rejection tests pass.

## Remaining gate

Wire real pgvector embeddings/full-text ranking, pin the embedding model, add re-embedding jobs, and verify analytics against SQL hand calculations.

## Decisions / constraints

See ADR 0004, 0006 and `docs/phases/implementation-status.md`. The source attachment contained the plan, not the previous full repository; module and database integration still needs verification against the real project. No measured performance, accuracy, novelty or production-safety claims are made without the planned experiments and infrastructure tests.
