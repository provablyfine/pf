"""restore_missing_autoincrement

Revision ID: 6356a7f48b37
Revises: 6aa7c4c69d90
Create Date: 2026-08-12 14:56:00.000000

"""

import alembic.op as op

# revision identifiers, used by Alembic.
revision: str = "6356a7f48b37"
down_revision: str | None = "6aa7c4c69d90"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # tenant was never created with sqlite_autoincrement=True, so a deleted tenant's id could
    # be reused by a later tenant. This migration changes no columns or data, it only adds
    # real AUTOINCREMENT to the table.
    with op.batch_alter_table("tenant", schema=None, recreate="always", table_kwargs={"sqlite_autoincrement": True}):
        pass
