"""session_logged_out_at

Revision ID: c8d1e4f7a2b9
Revises: a7e3c9f21b48
Create Date: 2026-09-19 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c8d1e4f7a2b9"
down_revision: str | None = "a7e3c9f21b48"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("identity_session_key", schema=None) as batch_op:
        batch_op.add_column(sa.Column("logged_out_at", sa.Integer(), nullable=True))
