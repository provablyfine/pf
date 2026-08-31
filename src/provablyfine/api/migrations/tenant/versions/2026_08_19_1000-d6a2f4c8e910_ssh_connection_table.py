"""ssh_connection_table

Revision ID: d6a2f4c8e910
Revises: b8f3c07d9e14
Create Date: 2026-08-19 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d6a2f4c8e910"
down_revision: str | None = "b8f3c07d9e14"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "ssh_connection",
        sa.Column("connection_id", sa.String(), nullable=False),
        sa.Column("identity_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("deadline", sa.Integer(), nullable=True),
        sa.Column("valid_before", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("connection_id"),
    )
    op.create_index("idx_ssh_connection_valid_before", "ssh_connection", ["valid_before"])
