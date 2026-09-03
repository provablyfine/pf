"""oidc_nonce_table

Revision ID: 8f78e75d9220
Revises: e2b2f7167f7a
Create Date: 2026-07-27 10:00:00.000000

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "8f78e75d9220"
down_revision: str | None = "e2b2f7167f7a"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "oidc_nonce",
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("nonce"),
    )
