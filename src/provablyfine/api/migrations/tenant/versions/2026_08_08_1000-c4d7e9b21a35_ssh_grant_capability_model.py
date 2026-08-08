"""ssh_grant_capability_model

Rewrite stored ssh-shell / ssh-port-forwarding / ssh-command grants into the
single `ssh` grant type.

The mapping below is a frozen copy of `model.grant.upcast` as it stood when
this migration was written, deliberately expressed over plain dicts. A
migration has to stay runnable against an old database forever, so it cannot
depend on live model code that later releases are free to delete -- and the
legacy grant types are deleted in the release that follows this one.
`test_tenant_migration_upcasts_ssh_grants` pins the behaviour.

Revision ID: c4d7e9b21a35
Revises: 3f1a92c8b4e5
Create Date: 2026-08-08 10:00:00.000000

"""

import typing

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c4d7e9b21a35"
down_revision: str | None = "3f1a92c8b4e5"
branch_labels: str | None = None
depends_on: str | None = None

_LEGACY_TYPES = ("ssh-shell", "ssh-port-forwarding", "ssh-command")

# Legacy shell issuance hardcoded permit_pty and permit_user_rc on, and
# permit_port_forwarding off, so an ssh-shell grant maps to exactly these.
_SHELL_CAPABILITIES = ["shell", "pty", "user-rc"]

_TABLES = [
    sa.table("role", sa.column("id", sa.Integer), sa.column("grant_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("ceiling_list", sa.JSON)),
    sa.table("boundary", sa.column("id", sa.Integer), sa.column("denied_list", sa.JSON)),
]

_Grant = dict[str, typing.Any]


def _upcast(g: _Grant) -> _Grant | None:
    """None means the grant denoted no atoms at all and is dropped."""
    permission: dict[str, typing.Any] = g["permission"]
    match g["type"]:
        case "ssh-shell":
            capability_list = list(_SHELL_CAPABILITIES)
            if permission.get("permit_agent_forwarding", False):
                capability_list.append("agent-forwarding")
            if permission.get("permit_x11_forwarding", False):
                capability_list.append("x11-forwarding")
            command_list: list[str] = []
        case "ssh-port-forwarding":
            capability_list = ["port-forwarding"]
            command_list = []
        case "ssh-command":
            capability_list = []
            command_list = list(permission["command_list"])
            if not command_list:
                return None
        case _:
            assert False, g["type"]
    return {
        "type": "ssh",
        "filter": g["filter"],
        "permission": {
            "username_list": permission["username_list"],
            "capability_list": capability_list,
            "command_list": command_list,
        },
    }


def _upgrade_grant_list(grant_list: list[_Grant]) -> list[_Grant]:
    output: list[_Grant] = []
    for g in grant_list:
        if g.get("type") not in _LEGACY_TYPES:
            output.append(g)
            continue
        # Dropping a no-atom entry is exact in every position: it granted
        # nothing, denied nothing, and contributed nothing to a ceiling union.
        if (upcast := _upcast(g)) is not None:
            output.append(upcast)
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
