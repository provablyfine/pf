"""bastion_tag_id_list_nullable

An empty `tag_id_list` on a bastion used to mean "every identity sees it." It
now means "no identity sees it," matching the None/[] convention already used
elsewhere (see #137). Existing bastions stored with `[]` are rewritten to
`NULL` here so they keep their current "visible to everyone" behavior across
the upgrade.

Revision ID: 736d98eea63f
Revises: c8d1e4f7a2b9
Create Date: 2026-09-27 17:09:34.313196

"""

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "736d98eea63f"
down_revision: str | None = "c8d1e4f7a2b9"
branch_labels: str | None = None
depends_on: str | None = None

_bastion = sa.table("bastion", sa.column("id", sa.Integer), sa.column("tag_id_list", sa.JSON))


def upgrade() -> None:
    """Upgrade schema."""
    connection = op.get_bind()
    for row_id, tag_id_list in connection.execute(sa.select(_bastion.c.id, _bastion.c.tag_id_list)):
        if tag_id_list == []:
            connection.execute(sa.update(_bastion).where(_bastion.c.id == row_id).values(tag_id_list=None))

    with op.batch_alter_table("bastion", schema=None, table_kwargs={"sqlite_autoincrement": True}) as batch_op:
        batch_op.alter_column("tag_id_list", existing_type=sa.JSON(), nullable=True)
