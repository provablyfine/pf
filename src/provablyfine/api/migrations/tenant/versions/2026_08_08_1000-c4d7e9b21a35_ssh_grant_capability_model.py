"""ssh_grant_capability_model

Rewrite stored ssh-shell / ssh-port-forwarding / ssh-command grants into the
single `ssh` grant type. `provablyfine.api.model.grant.upcast` is the executable specification
of this mapping and is reused verbatim, so the migration cannot drift from the
runtime semantics.

Revision ID: c4d7e9b21a35
Revises: 3f1a92c8b4e5
Create Date: 2026-08-08 10:00:00.000000

"""

import typing

import alembic.op as op
import sqlalchemy as sa

import provablyfine.api.model

# revision identifiers, used by Alembic.
revision: str = "c4d7e9b21a35"
down_revision: str | None = "3f1a92c8b4e5"
branch_labels: str | None = None
depends_on: str | None = None

_LEGACY_TYPES = ("ssh-shell", "ssh-port-forwarding", "ssh-command")

_TABLES = [
    sa.table("role", sa.column("id", sa.Integer), sa.column("grant_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("ceiling_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("denied_list", sa.JSON)),
]


def _upgrade_grant_list(grant_list: list[dict[str, typing.Any]]) -> list[dict[str, typing.Any]]:
    output: list[dict[str, typing.Any]] = []
    for g in grant_list:
        if g.get("type") not in _LEGACY_TYPES:
            output.append(g)
            continue
        legacy = provablyfine.api.model.grant.deserialize(g)
        assert isinstance(
            legacy,
            provablyfine.api.model.grant.SSHShellGrant
            | provablyfine.api.model.grant.SSHPortForwardingGrant
            | provablyfine.api.model.grant.SSHCommandGrant,
        )
        upcast = provablyfine.api.model.grant.upcast(legacy)
        # None means the entry denoted no atoms at all -- an ssh-command grant
        # with an empty command_list. Dropping it is exact: it granted nothing,
        # denied nothing, and contributed nothing to a ceiling union.
        if upcast is not None:
            output.append(provablyfine.api.model.grant.serialize(upcast))
    return output


def upgrade() -> None:
    """Upgrade schema."""
    connection = op.get_bind()
    for table in _TABLES:
        id_column, list_column = table.c.id, list(table.c)[1]
        for row_id, grant_list in connection.execute(sa.select(id_column, list_column)):
            # A null ceiling_list means "no ceiling" and is left alone.
            if grant_list is None or not any(g.get("type") in _LEGACY_TYPES for g in grant_list):
                continue
            connection.execute(
                sa.update(table).where(id_column == row_id).values({list_column.name: _upgrade_grant_list(grant_list)})
            )
