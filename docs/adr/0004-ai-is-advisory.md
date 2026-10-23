# ADR 0004: AI outputs are advisory

**Status:** Accepted.

Guidance and history modules return schema-checked suggestions with evidence/case citations. They do not import the pure verdict adjudicator, do not write directly to capsule versions, and require a human reviewer before a suggestion can become an approved capsule. If the deterministic dry-run capability is not configured, approval fails closed.
