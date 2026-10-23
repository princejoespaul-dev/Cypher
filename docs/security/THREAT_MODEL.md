# CYPHER backend threat model (v1)

## In scope

- Authorization bypass testing of owned sandbox APIs (BOLA/IDOR).
- Evidence confidentiality and integrity, cross-project access, accidental off-target traffic, destructive test side effects, prompt injection in target data, and AI-generated unsafe capsules.
- Unintentional service overexposure, secret leaks in logs/prompts, job replay/idempotency misuse, and misleading evaluation claims.

## Required controls

1. Sandbox-only targets, explicit per-target host allowlists, DNS revalidation and address pinning, no off-list redirects, internal sandbox network with no public target ports.
2. Read-only database oracle, one parameterized SELECT probe per stored oracle definition, read-only privilege proof before state snapshots.
3. Secret/token redaction before persistence and model prompts. Secret values are referenced by names, not embedded in capsules.
4. Project scoping on every data access and PostgreSQL RLS as defense in depth. API keys are hashed at rest in the persistent implementation.
5. Append-only observations, state snapshots, verdicts, finding events, capsule versions, reviewed cases and audit entries.
6. Deterministic adjudication only; AI results are advisory, validated and human-approved.
7. Rate/concurrency/token/cost caps and bounded request size/timeouts.

## Not yet established

The repository-level tests do not prove production deployment safety. Container egress isolation, database grants/RLS, append-only triggers, DNS rebinding defenses through the real HTTP stack, encrypted backups, KMS integration, key rotation, deployment hardening, dependency/image vulnerability scans and operational incident handling need integration and deployment validation. Do not use on production or third-party systems.
