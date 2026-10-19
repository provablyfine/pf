"""tenant_retention

Revision ID: d4e7a2b95c18
Revises: c8d24e7a1f93
Create Date: 2026-10-19 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d4e7a2b95c18"
down_revision: str | None = "c8d24e7a1f93"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing tenants keep a full year, so that upgrading deletes nothing.
    with op.batch_alter_table("tenant", schema=None, table_kwargs={"sqlite_autoincrement": True}) as batch_op:
        batch_op.add_column(sa.Column("audit_retention_days", sa.Integer(), nullable=False, server_default="365"))
        batch_op.add_column(sa.Column("activity_retention_days", sa.Integer(), nullable=False, server_default="365"))
        batch_op.add_column(
            sa.Column("retention_purge_enabled", sa.Boolean(), nullable=False, server_default=sa.true())
        )
