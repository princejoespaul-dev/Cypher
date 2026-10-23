# ADR 0001: Modular monolith

**Status:** Accepted for research prototype.

## Decision

Use one typed Python codebase with explicit module boundaries, one REST API process, separate worker processes, PostgreSQL/pgvector, Redis queueing and Docker-managed reference targets.

## Rationale

This keeps phase-to-phase contracts testable and affordable for a small team while allowing modules to split later. AI advisory code remains outside the deterministic adjudicator's import path.

## Consequences

A deployment is not considered production-ready until the persistent repository, queue, secrets manager, object store and sandbox worker are wired and tested together.
