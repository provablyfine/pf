"""restore_missing_autoincrement

Revision ID: 5052f9d083ee
Revises: 5045f5101bb7
Create Date: 2026-08-12 14:56:00.000000

"""

import alembic.op as op

# revision identifiers, used by Alembic.
revision: str = "5052f9d083ee"
down_revision: str | None = "5045f5101bb7"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Below table were never created with sqlite_autoincrement=True, as a result their deleted ids could be reused.
    # This migration changes no columns or data, it only adds AUTOINCREMENT to these tables.
    for table in ("auth", "identity_boundary", "identity_tag", "role_member", "default", "audit_log"):
        with op.batch_alter_table(table, schema=None, recreate="always", table_kwargs={"sqlite_autoincrement": True}):
            pass
