"""Phase 1 base schema: tenant model, auth, capsule/replay/evidence and audit tables."""
from pathlib import Path
from alembic import op

revision = "cypher_phase1_core"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    path = Path(__file__).resolve().parents[1] / "001_core_schema.sql"
    op.get_bind().exec_driver_sql(path.read_text(encoding="utf-8"))


def downgrade() -> None:
    # Destructive data removal is only valid for a disposable development database.
    op.get_bind().exec_driver_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
