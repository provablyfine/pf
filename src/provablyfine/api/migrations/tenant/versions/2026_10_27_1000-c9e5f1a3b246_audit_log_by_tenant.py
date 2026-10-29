"""audit_log_by_tenant

Name the tenant of an author who belongs to another tenant.
The identity id of such an author means nothing here.

Revision ID: c9e5f1a3b246
Revises: b8d4e0f2a135
Create Date: 2026-10-27 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c9e5f1a3b246"
down_revision: str | None = "b8d4e0f2a135"
branch_labels: str | None = None
depends_on: str | None = None

# SQLite's batch mode drops sqlite_autoincrement when it rebuilds a table.
_AUTOINCREMENT = {"sqlite_autoincrement": True}


def upgrade() -> None:
    """Upgrade schema."""
    text = sa.String().with_variant(sa.String(255), "mysql", "mariadb")
    with op.batch_alter_table("audit_log", schema=None, table_kwargs=_AUTOINCREMENT) as batch_op:
        batch_op.add_column(sa.Column("by_tenant_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("by_tenant_name", text, nullable=True))
        batch_op.create_index("idx_audit_log_by_tenant_id", ["by_tenant_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("audit_log", schema=None, table_kwargs=_AUTOINCREMENT) as batch_op:
        batch_op.drop_index("idx_audit_log_by_tenant_id")
        batch_op.drop_column("by_tenant_name")
        batch_op.drop_column("by_tenant_id")
