"""identity_restore_autoincrement

Revision ID: 5045f5101bb7
Revises: 3f1a92c8b4e5
Create Date: 2026-08-08 10:00:00.000000

"""

import alembic.op as op

# revision identifiers, used by Alembic.
revision: str = "5045f5101bb7"
down_revision: str | None = "3f1a92c8b4e5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # The baseline schema created "identity" with sqlite_autoincrement=True, so deleted ids
    # could never be reused. The uix_identity_name and identity_posix_fields migrations both
    # rebuilt the table via batch_alter_table to add a UNIQUE constraint, and neither re-passed
    # sqlite_autoincrement. SQLite's batch mode silently dropped it on both rebuilds.
    # This migration changes no columns or data, it only restores real AUTOINCREMENT.
    with op.batch_alter_table("identity", schema=None, recreate="always", table_kwargs={"sqlite_autoincrement": True}):
        pass
