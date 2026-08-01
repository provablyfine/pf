"""tenant_unix_settings

Revision ID: c1a2e9d47b6f
Revises: 6aa7c4c69d90
Create Date: 2026-07-31 14:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c1a2e9d47b6f"
down_revision: str | None = "6aa7c4c69d90"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("tenant", schema=None) as batch_op:
        batch_op.add_column(sa.Column("unix_mode", sa.String(), nullable=False, server_default="manual"))
