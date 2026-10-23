# Reference API (sandbox only)

This intentionally vulnerable FastAPI orders service provides `vulnerable`, `fixed`, `partial_fix`, `over_blocking`, and `reintroduced` variants through `CYPHER_VARIANT`. Fixture bearer tokens are `fixture-token-user-a` and `fixture-token-user-b`. It is designed for local, isolated security regression tests only; do not expose it on a public interface. The `/internal/*` routes must be reachable only from the sandbox worker network.

Variant construction is intentionally explicit so the benchmark ground-truth file can be reviewed before tests run. `partial_fix` protects reads but leaves the write route vulnerable; `over_blocking` blocks the owner control as well.
