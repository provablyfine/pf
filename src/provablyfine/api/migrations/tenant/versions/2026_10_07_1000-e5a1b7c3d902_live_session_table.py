"""live_session_table

Revision ID: e5a1b7c3d902
Revises: d4f0a9c6b217
Create Date: 2026-10-07 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "e5a1b7c3d902"
down_revision: str | None = "d4f0a9c6b217"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "live_session",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("connection_id", sa.String(), nullable=False),
        sa.Column("identity_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("started_at", sa.Integer(), nullable=False),
        sa.Column("ended_at", sa.Integer(), nullable=True),
        sa.Column("deadline", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_live_session_unique", "live_session", ["connection_id", "kind", "session_id"], unique=True)
    op.create_index("idx_live_session_hostname", "live_session", ["hostname"])
    op.create_index("idx_live_session_ended_at", "live_session", ["ended_at"])
