# Phase 2 report — AIC and policy registry

**Status:** Implemented in the reconstructed codebase; integration gate remains partial.

## Built

Added strict Pydantic AIC models, schema output, policy versions, canonical hashing/fingerprinting, schema/reference/safety/minimality validators and append-only capsule version/status lifecycle.

## Verification

Domain validators and version lifecycle covered by unit tests.

## Remaining gate

Expand the plan’s 20 positive/40 negative capsule fixture set; verify RFC 8785 vectors/cross-runtime hash identity; connect persistent policy/capsule service.

## Decisions / constraints

See ADR 0002 and `docs/phases/implementation-status.md`. The source attachment contained the plan, not the previous full repository; module and database integration still needs verification against the real project. No measured performance, accuracy, novelty or production-safety claims are made without the planned experiments and infrastructure tests.
