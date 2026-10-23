"""Conservative read-only SQL probe validation.

Only a single SELECT statement is accepted. The deliberately restricted syntax rejects
CTEs, comments, semicolons, data-modifying statements, locking clauses and file/system
functions. A real DB read-only credential and transaction policy are still mandatory.
"""
from __future__ import annotations

import re


class UnsafeProbe(ValueError):
    pass

_COMMENT = re.compile(r"(--|/\*|\*/|#)")
_FORBIDDEN = re.compile(r"\b(insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|copy|call|execute|do|vacuum|analyze|refresh|set|reset|pg_read_file|pg_ls_dir|dblink|lo_export|lo_import|into|for\s+(update|share))\b", re.I)


def validate_select_probe(sql: str) -> str:
    value = sql.strip()
    if not value or len(value) > 8_000:
        raise UnsafeProbe("Probe is empty or exceeds the maximum length")
    if _COMMENT.search(value):
        raise UnsafeProbe("Comments are not permitted in a state-oracle probe")
    if ";" in value.rstrip(";") or value.rstrip(";").count(";"):
        raise UnsafeProbe("Only one SQL statement may be used")
    if value.endswith(";"):
        value = value[:-1].rstrip()
    if not re.match(r"^SELECT\b", value, re.I):
        raise UnsafeProbe("State-oracle probes must be one SELECT statement; CTEs are not accepted")
    if _FORBIDDEN.search(value):
        raise UnsafeProbe("Probe contains a forbidden SQL operation or function")
    if "\x00" in value:
        raise UnsafeProbe("NUL bytes are forbidden")
    return value

class PostgresStateOracle:
    """Direct read-only DB oracle; the DSN resolver must return a sandbox-only DSN.

    A dedicated role with SELECT-only grants and a transaction-level READ ONLY mode are
    both required. Probe names and SQL must come from the target's reviewed registry.
    """
    def __init__(self, *, dsn_resolver, allowed_probes: dict[str, str], evidence_writer=None, engine_factory=None) -> None:
        self._dsn_resolver = dsn_resolver
        self._probes = {name: validate_select_probe(sql) for name, sql in allowed_probes.items()}
        self._evidence_writer = evidence_writer
        self._engine_factory = engine_factory

    def prove_read_only(self, *, environment_id, project_id) -> None:
        from sqlalchemy import create_engine, text
        dsn = self._dsn_resolver(environment_id=environment_id, project_id=project_id)
        factory = self._engine_factory or create_engine
        engine = factory(dsn, pool_pre_ping=True, connect_args={"options": "-c default_transaction_read_only=on"})
        try:
            with engine.connect() as conn:
                tx = conn.begin()
                try:
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                    # This SELECT must succeed; a missing table is not evidence of read-only enforcement.
                    conn.execute(text("SELECT id FROM cypher_oracle_sentinel LIMIT 1")).all()
                    conn.execute(text("UPDATE cypher_oracle_sentinel SET id=id WHERE false"))
                except Exception as exc:
                    tx.rollback()
                    original = getattr(exc, "orig", exc)
                    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
                    if sqlstate in {"25006", "42501"}:
                        return
                    raise RuntimeError("oracle.read_only_unproven: write attempt failed for a reason other than database read-only enforcement") from exc
                tx.rollback()
                raise RuntimeError("oracle.read_only_unproven: the state oracle connection allowed a write")
        finally:
            engine.dispose()

    def probe_hashes(self, *, environment_id, project_id, probe_names: tuple[str, ...]) -> dict[str, str]:
        from sqlalchemy import create_engine, text
        unknown = set(probe_names) - set(self._probes)
        if unknown:
            raise UnsafeProbe(f"Unknown state-oracle probe names: {', '.join(sorted(unknown))}")
        dsn = self._dsn_resolver(environment_id=environment_id, project_id=project_id)
        factory = self._engine_factory or create_engine
        engine = factory(dsn, pool_pre_ping=True, connect_args={"options": "-c default_transaction_read_only=on"})
        results: dict[str, str] = {}
        try:
            with engine.connect() as conn:
                with conn.begin():
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                    for name in probe_names:
                        sql = validate_select_probe(self._probes[name])
                        rows = conn.execute(text(sql)).mappings().all()
                        from cypher.core.canonical import canonical_json_bytes, sha256_hex
                        from cypher.evidence.redaction import redact_value
                        canonical_rows, _ = redact_value([dict(row) for row in rows])
                        blob = canonical_json_bytes(canonical_rows, permit_float=True)
                        digest = sha256_hex(blob)
                        results[name] = digest
                        if self._evidence_writer is not None:
                            self._evidence_writer(project_id=project_id, environment_id=environment_id,
                                                  probe_name=name, data=blob, content_sha256=digest)
        finally:
            engine.dispose()
        return results
