"""identity_posix_fields

Revision ID: 3f1a92c8b4e5
Revises: 8f78e75d9220
Create Date: 2026-07-28 09:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "3f1a92c8b4e5"
down_revision: str | None = "8f78e75d9220"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("identity", schema=None) as batch_op:
        batch_op.add_column(sa.Column("unix_username", sa.String(), nullable=True))
        batch_op.create_unique_constraint("uix_identity_unix_username", ["unix_username"])
