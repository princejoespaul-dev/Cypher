"""Alembic wrapper for the reconstructed Phase 5 schema.

This checkout links Phase 5 to its included base revision. When merging into the
original Cypher repository, reconcile this synthetic revision chain with the
actual Phase 0-4 migrations before applying it to any persistent database.
"""
from pathlib import Path

from alembic import op

revision = "cypher_phase5_fix_recurrence"
down_revision = "cypher_phase1_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql_path = Path(__file__).resolve().parents[1] / "phase5_findings_fix_recurrence.sql"
    op.get_bind().exec_driver_sql(sql_path.read_text(encoding="utf-8"))


def downgrade() -> None:
    # Destructive rollback is intentionally omitted for immutable security evidence.
    # Roll back the migration only in a disposable development database using an
    # explicitly reviewed reverse migration; do not delete findings or verdict history.
    raise RuntimeError("Phase 5 stores immutable security evidence; use an approved reverse migration for disposable databases only")
