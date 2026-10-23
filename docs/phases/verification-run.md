# Final verification run — 23 October 2026

Commands executed from the repository root:

```bash
PYTHONPATH=src pytest -q
python -m compileall -q src migrations scripts
PYTHONPATH=src python scripts/export_openapi.py
PYTHONPATH=src python scripts/export_openapi.py --check
```

Results:

- Unit/API-adapter tests: **57 passed**.
- Python source, migrations and scripts compiled successfully.
- OpenAPI export and consistency check passed: **45 paths, 48 operations**.
- `pyproject.toml` parsed as valid TOML.
- `docker-compose.yml` parsed as valid YAML; services: `postgres`, `redis`, `minio`, `api`, `reference-vulnerable`, `reference-fixed`.

Not verified by this run: Docker image builds, live container networking and egress isolation, actual PostgreSQL migration execution and RLS/trigger behavior, durable queue/object-store integration, full public-API replay, provider-backed LLM calls, strict mypy/import-linter and a transitive hash-locked install. Those are explicit integration/release gates, not implied by the unit-test result.
