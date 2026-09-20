"""tenant_name_not_unique

Revision ID: c8d24e7a1f93
Revises: b1f3a9c25d70
Create Date: 2026-09-20 11:00:00.000000

"""

import alembic.op as op

# revision identifiers, used by Alembic.
revision: str = "c8d24e7a1f93"
down_revision: str | None = "b1f3a9c25d70"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # A tenant is addressed by its UUID, so its name does not have to be unique.
    # A unique name would let a caller find out which names other tenants use.
    # The baseline constraint has no name: the naming convention gives it one so that it can be dropped.
    with op.batch_alter_table(
        "tenant",
        schema=None,
        table_kwargs={"sqlite_autoincrement": True},
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch_op:
        batch_op.drop_constraint("uq_tenant_name", type_="unique")
