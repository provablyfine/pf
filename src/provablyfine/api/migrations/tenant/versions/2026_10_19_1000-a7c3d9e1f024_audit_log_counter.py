"""audit_log_counter

Hand out audit entry ids from a counter that is locked until the commit.
Entries are then numbered in the order they commit, and a reader that has seen entry N has seen all below N.

Revision ID: a7c3d9e1f024
Revises: f6b2c8d4e013
Create Date: 2026-10-19 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a7c3d9e1f024"
down_revision: str | None = "f6b2c8d4e013"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "audit_log_counter",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("value", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # The next entry takes the id after the highest one that exists.
    last = op.get_bind().execute(sa.text("SELECT COALESCE(MAX(id), 0) FROM audit_log")).scalar_one()
    op.get_bind().execute(sa.text("INSERT INTO audit_log_counter (id, value) VALUES (1, :value)"), {"value": last})


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("audit_log_counter")
