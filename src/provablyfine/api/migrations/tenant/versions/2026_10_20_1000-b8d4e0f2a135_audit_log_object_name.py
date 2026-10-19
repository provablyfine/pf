"""audit_log_object_name

Keep the names that each object had, one row per object and name.
Finding the objects that ever had a name is then a plain read.

Revision ID: b8d4e0f2a135
Revises: a7c3d9e1f024
Create Date: 2026-10-20 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b8d4e0f2a135"
down_revision: str | None = "a7c3d9e1f024"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    text = sa.String().with_variant(sa.String(255), "mysql", "mariadb")
    op.create_table(
        "audit_log_object_name",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("object_type", text, nullable=False),
        sa.Column("object_id", text, nullable=False),
        sa.Column("object_name", text, nullable=False),
        sa.Column("first_entry_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("object_type", "object_id", "object_name", name="uq_audit_log_object_name"),
        sqlite_autoincrement=True,
    )
    with op.batch_alter_table("audit_log_object_name", schema=None) as batch_op:
        batch_op.create_index("idx_audit_log_object_name_name", ["object_type", "object_name"], unique=False)
        batch_op.create_index("idx_audit_log_object_name_object", ["object_type", "object_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("audit_log_object_name")
