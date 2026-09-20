"""tenant_uuid

Revision ID: b1f3a9c25d70
Revises: 6356a7f48b37
Create Date: 2026-09-20 10:00:00.000000

"""

import uuid

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b1f3a9c25d70"
down_revision: str | None = "6356a7f48b37"
branch_labels: str | None = None
depends_on: str | None = None

# Duplicated from registry_db on purpose: a migration must not change when the module does.
_ROOT_TENANT_UUID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("tenant", schema=None) as batch_op:
        batch_op.add_column(sa.Column("uuid", sa.String(), nullable=True))

    connection = op.get_bind()
    tenant = sa.table(
        "tenant", sa.column("id", sa.Integer()), sa.column("name", sa.String()), sa.column("uuid", sa.String())
    )
    for row in connection.execute(sa.select(tenant.c.id, tenant.c.name)).all():
        value = _ROOT_TENANT_UUID if row.name == "root" else str(uuid.uuid4())
        connection.execute(sa.update(tenant).where(tenant.c.id == row.id).values(uuid=value))

    with op.batch_alter_table("tenant", schema=None, table_kwargs={"sqlite_autoincrement": True}) as batch_op:
        batch_op.alter_column("uuid", existing_type=sa.String(), nullable=False)
        batch_op.create_unique_constraint("uq_tenant_uuid", ["uuid"])
