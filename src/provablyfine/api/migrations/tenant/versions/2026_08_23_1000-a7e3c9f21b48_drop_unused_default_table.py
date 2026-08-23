"""drop_unused_default_table

Revision ID: a7e3c9f21b48
Revises: 5052f9d083ee
Create Date: 2026-08-23 10:00:00.000000

"""

import alembic.op as op

# revision identifiers, used by Alembic.
revision: str = "a7e3c9f21b48"
down_revision: str | None = "5052f9d083ee"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_table("default")
