# Phase 9 report — Experiments and reproducibility

**Status:** Implemented in the reconstructed codebase; integration gate remains partial.

## Built

Added validated experiment config, arm/seed/repeat runner, manifest and hash export, deterministic metric functions and committed reference ground-truth labels.

## Verification

Metrics and export integrity/reproducibility unit tests pass.

## Remaining gate

Build the actual public benchmark target, pre-register thresholds, execute arms A–F and three reruns; publish confidence intervals and both positive/negative results.

## Decisions / constraints

See ADR 0006 and `docs/phases/implementation-status.md`. The source attachment contained the plan, not the previous full repository; module and database integration still needs verification against the real project. No measured performance, accuracy, novelty or production-safety claims are made without the planned experiments and infrastructure tests.
