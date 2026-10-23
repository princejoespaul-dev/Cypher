# CYPHER implementation status — 23 October 2026

This status describes the code reconstructed from `Backend Plan.md` plus the earlier Phase 5 implementation bundle. The original pre-existing Phase 0–4 repository was not available in the uploaded material, so this is not certified as a merge into that repository.

| Plan phase | Code present | Tests run in this environment | Full phase gate status |
|---|---|---:|---|
| 0 — Foundations | Package layout, settings, API health/readiness, logging/error helpers, Compose/Make/CI skeleton | Yes, unit/API tests | **Partial** — no live Compose CI run; no complete lockfile; module-linter/strict typecheck not verified |
| 1 — Data model/auth/audit | PostgreSQL DDL, Alembic base migration, API-key/RBAC, project-scoped in-memory adapters, hash-chained audit, secrets interface | Yes, unit/API tests | **Partial** — real PostgreSQL migration/RLS/trigger and two-project DB checks not run |
| 2 — AIC/policy | Strict capsule models, schemas, content hash/fingerprint, reference validation, minimality checks, policy versions/lifecycle | Yes, unit tests | **Partial** — plan's 20-valid/40-invalid fixture set and cross-platform RFC 8785 conformance suite remain to be run/expanded |
| 3 — Sandbox/targets/builds | Reference API variants, Docker manager/build helper, seed/state-oracle interfaces, host checks | Yes, unit tests | **Partial** — Docker build/reset timing, true no-egress verification and live read-only DB proof not run |
| 4 — Replay/verdict | Request renderer, redacting executor/evidence store, replay orchestration interfaces, pure ordered adjudicator, completeness/repeat handling | Yes, unit tests | **Partial** — live controlled target replay, repeat/flaky e2e and golden vectors in the full stack not run |
| 5 — Findings/fix/recurrence | Findings/event history, four fix outcomes, suite-failed gating, append-only re-adjudication | 22 dedicated Phase 5 tests; included in 57-test suite | **Partial** — original repository migration chain/real PostgreSQL integration unavailable |
| 6 — Deterministic freeze | Core security tests and threat model; no AI imports from pure adjudicator | Unit tests | **Not frozen** — no complete governance matrix, API-only e2e or Cypher dogfood run against a persistent service |
| 7 — Cyphrun/guidance | LLM protocol/fake/adapter, budget ledger, context validation, suggestions, explanations, approval gate | Unit tests | **Partial** — provider-backed model comparison, injection suite at planned breadth, recorded-output replays and real cost tests pending |
| 8 — Cyphrus/history | Case lifecycle/review freezing, keyword/vector-ready retrieval abstraction, citations and deterministic recurrence analytics | Unit tests | **Partial** — real pgvector embedding/storage, re-embed job and hand-calculated DB-view fixtures not verified |
| 9 — Experiments | Config/metrics/manifest/reproduce helper, ground-truth file and arm model | Unit tests | **Partial** — no full benchmark run; no observed precision/recall/novelty/performance claim is made |

## Verification performed

- `PYTHONPATH=src pytest -q`: **57 passed**.
- Python bytecode compilation of source/migrations/scripts.
- `scripts/export_openapi.py` export and `--check`: **45 paths / 48 operations**.
- `pyproject.toml` parsed as valid TOML; `docker-compose.yml` parsed as valid YAML with six declared services.
- Container-backed validation was not run: Docker/PostgreSQL runtime and database service were unavailable.

## Blockers before calling it complete

1. Connect the actual Compose environment, Postgres session factory/RLS `SET app.project_id`, Redis/worker dispatcher and S3-compatible store into the API composition root.
2. Run every Alembic migration from a brand-new PostgreSQL instance; test rollback policy, append-only triggers, RLS and audit tamper detection with separate projects/roles.
3. Execute the whole replay via only the public API against all five container variants, test repeat determinism, external egress block, DNS/IP bypasses, read-only oracle, and recovery after destructive operations.
4. Generate a transitive hash lock and pin container images by immutable digests; run dependency/image scans and strict type/import-linter CI.
5. Implement and execute the remaining experiment recipes with ground-truth labels set before runs. Publish negative/positive results honestly.
