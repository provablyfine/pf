"""ssh_grant_max_session_ttl

Add `max_session_ttl_s: null` to every stored `ssh` grant.

The field is required and `SSHPermission` forbids extra keys, both on purpose:
a stored grant is a security document, and a schema default would be invisible
semantics for whoever reads it. The cost of that choice is this migration --
without it, every `ssh` grant written before this release fails validation and
its role or boundary becomes unreadable.

`null` is the whole axis, i.e. unbounded, which is exactly the behaviour those
grants had when the field did not exist.

Like its predecessor this operates on plain dicts and imports nothing from the
model layer, so it stays runnable after a later release changes the schema.

Revision ID: b8f3c07d9e14
Revises: c4d7e9b21a35
Create Date: 2026-08-08 14:00:00.000000

"""

import typing

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b8f3c07d9e14"
down_revision: str | None = "c4d7e9b21a35"
branch_labels: str | None = None
depends_on: str | None = None

_FIELD = "max_session_ttl_s"

_TABLES = [
    sa.table("role", sa.column("id", sa.Integer), sa.column("grant_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("ceiling_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("denied_list", sa.JSON)),
]

_Grant = dict[str, typing.Any]


def _needs_field(grant_list: list[_Grant] | None) -> bool:
    if grant_list is None:  # a null ceiling_list means "no ceiling"
        return False
    return any(g.get("type") == "ssh" and _FIELD not in g["permission"] for g in grant_list)


def _upgrade_grant_list(grant_list: list[_Grant]) -> list[_Grant]:
    output: list[_Grant] = []
    for g in grant_list:
        if g.get("type") != "ssh":
            output.append(g)
            continue
        output.append({**g, "permission": {**g["permission"], _FIELD: None}})
    return output


def upgrade() -> None:
    """Upgrade schema."""
    connection = op.get_bind()
    for table in _TABLES:
        id_column, list_column = table.c.id, list(table.c)[1]
        for row_id, grant_list in connection.execute(sa.select(id_column, list_column)):
            if not _needs_field(grant_list):
                continue
            connection.execute(
                sa.update(table).where(id_column == row_id).values({list_column.name: _upgrade_grant_list(grant_list)})
            )
