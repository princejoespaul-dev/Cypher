# ADR 0007: Provisional direct dependency pins

**Status:** Provisional; release verification required.

## Decision

Use explicit direct dependency pins rather than unconstrained ranges. The base FastAPI/Pydantic/SQLAlchemy and test libraries were available in this implementation environment and passed the unit suite. Optional Docker, Redis and PostgreSQL client SDK pins are selected but were not install-tested here because those packages were absent and the package index was unavailable.

## Consequences

The repository intentionally does not claim a complete reproducible installation yet. Before release, resolve the full dependency graph in a network-enabled environment, compare current supported stable releases, generate a hash-pinned `uv.lock`, install from that lock in clean CI, and scan dependency artifacts. Do not silently update applied production environments.
