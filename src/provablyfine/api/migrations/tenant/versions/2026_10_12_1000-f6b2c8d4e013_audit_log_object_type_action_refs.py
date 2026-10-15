"""audit_log_object_type_action_refs

Split the audit entry type into an object type and an action.
Name the objects an entry is about in a table that can be searched.

Revision ID: f6b2c8d4e013
Revises: e5a1b7c3d902
Create Date: 2026-10-12 10:00:00.000000

"""

import typing

import alembic.op as op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f6b2c8d4e013"
down_revision: str | None = "e5a1b7c3d902"
branch_labels: str | None = None
depends_on: str | None = None

# SQLite's batch mode drops sqlite_autoincrement when it rebuilds a table.
_AUTOINCREMENT = {"sqlite_autoincrement": True}

# Entry type as it was stored -> (new object type, new action, key of `details` that holds the target id).
# The table is written out because the old strings cannot be split by a rule.
_TYPES: dict[str, tuple[str, str, str | None]] = {
    "identity-create": ("identity", "create", "id"),
    "identity-delete": ("identity", "delete", "id"),
    "identity-update-name": ("identity", "update-name", "id"),
    "identity-update-unix-username": ("identity", "update-unix-username", "id"),
    "identity-add-tags": ("identity", "add-tags", "id"),
    "identity-delete-tags": ("identity", "remove-tags", "id"),
    "identity-delete-refused": ("identity", "delete-refused", "identity_id"),
    "identity-delete-cascade": ("identity", "delete-cascade", "identity_id"),
    "identity-invitation-create": ("identity-invitation", "create", "id"),
    "identity-invitation-accepted": ("identity-invitation", "accepted", "id"),
    "role-create": ("role", "create", "id"),
    "role-delete": ("role", "delete", "id"),
    "role-update-name": ("role", "update-name", "id"),
    "role-update-description": ("role", "update-description", "id"),
    "role-update-grant-list": ("role", "update-grant-list", "id"),
    "role-add-members": ("role", "add-members", "id"),
    "role-delete-members": ("role", "remove-members", "id"),
    "boundary-create": ("boundary", "create", "id"),
    "boundary-delete": ("boundary", "delete", "id"),
    "boundary-update-name": ("boundary", "update-name", "id"),
    "boundary-update-description": ("boundary", "update-description", "id"),
    "boundary-update-ceiling-list": ("boundary", "update-ceiling-list", "id"),
    "boundary-update-denied-list": ("boundary", "update-denied-list", "id"),
    "tag-create": ("tag", "create", "id"),
    "tag-delete": ("tag", "delete", "id"),
    "tag-delete-cascade": ("tag", "delete-cascade", "tag_id"),
    "bastion-create": ("bastion", "create", "id"),
    "bastion-update": ("bastion", "update", "id"),
    "bastion-delete": ("bastion", "delete", "id"),
    "bastion-delete-cascade": ("bastion", "delete-cascade", "bastion_id"),
    "auth-create": ("auth", "create", "id"),
    "auth-update": ("auth", "update", "id"),
    "auth-delete": ("auth", "delete", "id"),
    "session-create": ("session", "login", "session_key_id"),
    "session-logout": ("session", "logout", "session_key_id"),
    "session-set-role": ("session", "set-role", "session_key_id"),
    "live-session-terminate": ("live-session", "terminate", "live_session_id"),
    "signing-key-create": ("signing-key", "create", "signing_key_id"),
    "signing-key-update-serial": ("signing-key", "update-serial", "id"),
    "create-user-certificate": ("certificate", "create-user", None),
    "create-host-certificate": ("certificate", "create-host", None),
    "denylist-add": ("public-key", "denylisted", "public_key_id"),
    "denylist-check-failed": ("public-key", "rejected", "public_key_id"),
}

# `details["refs"]` kinds and the live table each kind is named from.
_LIVE_NAMES: dict[str, tuple[str, str]] = {
    "identity": ("identity", "name"),
    "role": ("role", "name"),
    "boundary": ("boundary", "name"),
    "tag": ("tag", "name"),
    "bastion": ("bastion", "url"),
    "auth": ("auth", "name"),
}


def upgrade() -> None:
    """Upgrade schema."""
    # MySQL and MariaDB need a length for indexed strings. The tables declared in app_db.py use the same one.
    text = sa.String().with_variant(sa.String(255), "mysql", "mariadb")
    with op.batch_alter_table("audit_log", schema=None, table_kwargs=_AUTOINCREMENT) as batch_op:
        batch_op.add_column(sa.Column("object_type", text, nullable=True))
        batch_op.add_column(sa.Column("action", text, nullable=True))
        batch_op.add_column(sa.Column("by_identity_name", text, nullable=True))
    op.create_table(
        "audit_log_ref",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("entry_id", sa.Integer(), nullable=False),
        sa.Column("object_type", text, nullable=False),
        sa.Column("object_id", text, nullable=False),
        sa.Column("object_name", text, nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )

    connection = op.get_bind()
    _backfill(connection)

    with op.batch_alter_table("audit_log", schema=None, table_kwargs=_AUTOINCREMENT) as batch_op:
        batch_op.alter_column("object_type", existing_type=text, nullable=False)
        batch_op.alter_column("action", existing_type=text, nullable=False)
        batch_op.create_index("idx_audit_log_object_type_action", ["object_type", "action"], unique=False)
    with op.batch_alter_table("audit_log_ref", schema=None) as batch_op:
        batch_op.create_index("idx_audit_log_ref_entry_id", ["entry_id"], unique=False)
        batch_op.create_index("idx_audit_log_ref_object_id", ["object_type", "object_id"], unique=False)
        batch_op.create_index("idx_audit_log_ref_object_name", ["object_type", "object_name"], unique=False)


def _backfill(connection: sa.engine.Connection) -> None:
    audit_log = sa.table(
        "audit_log",
        sa.column("id", sa.Integer),
        sa.column("type", sa.String),
        sa.column("by_identity_id", sa.String),
        sa.column("details", sa.JSON),
        sa.column("object_type", sa.String),
        sa.column("action", sa.String),
        sa.column("by_identity_name", sa.String),
    )
    ref = sa.table(
        "audit_log_ref",
        sa.column("entry_id", sa.Integer),
        sa.column("object_type", sa.String),
        sa.column("object_id", sa.String),
        sa.column("object_name", sa.String),
    )

    live: dict[str, dict[str, str]] = {}
    for kind, (table_name, column_name) in _LIVE_NAMES.items():
        table = sa.table(table_name, sa.column("id", sa.Integer), sa.column(column_name, sa.String))
        live[kind] = {str(r[0]): r[1] for r in connection.execute(sa.select(table.c.id, table.c[column_name]))}

    rows = connection.execute(
        sa.select(audit_log.c.id, audit_log.c.type, audit_log.c.by_identity_id, audit_log.c.details)
    ).fetchall()
    for entry_id, old_type, by_identity_id, details in rows:
        details = typing.cast(dict[str, typing.Any], details) if isinstance(details, dict) else {}
        object_type, action, target_key = _TYPES.get(old_type, (old_type, "", None))
        new_type = f"{object_type}-{action}" if action else old_type
        by_name = live["identity"].get(str(by_identity_id)) if by_identity_id is not None else None
        connection.execute(
            audit_log.update()
            .where(audit_log.c.id == entry_id)
            .values(type=new_type, object_type=object_type, action=action, by_identity_name=by_name)
        )
        for found_type, found_id, found_name in _entry_refs(details, object_type, target_key, live):
            connection.execute(
                ref.insert().values(
                    entry_id=entry_id, object_type=found_type, object_id=found_id, object_name=found_name
                )
            )


def _text(details: dict[str, typing.Any], key: str) -> str | None:
    value: object = details.get(key)
    return None if value is None else str(value)


def _entry_refs(
    details: dict[str, typing.Any], object_type: str, target_key: str | None, live: dict[str, dict[str, str]]
) -> list[tuple[str, str, str | None]]:
    found: dict[tuple[str, str], str | None] = {}
    target_id = None if target_key is None else _text(details, target_key)
    if target_id is not None:
        name = _text(details, "name") or _text(details, "url") or live.get(object_type, {}).get(target_id)
        found[(object_type, target_id)] = name
    owner_type, owner_id = _text(details, "owner_type"), _text(details, "owner_id")
    if owner_type is not None and owner_id is not None:
        found[(owner_type, owner_id)] = _text(details, "owner_name")
    identity_id = _text(details, "identity_id")
    if identity_id is not None:
        found.setdefault(("identity", identity_id), live["identity"].get(identity_id))
    host_id = _text(details, "host_id")
    if host_id is not None:
        found.setdefault(("identity", host_id), _text(details, "hostname"))
    refs: dict[str, dict[str, dict[str, typing.Any] | None]] = details.get("refs") or {}
    for kind, by_id in refs.items():
        for object_id, label in by_id.items():
            name = None if label is None else _text(label, "name") or _text(label, "url")
            found.setdefault((kind, str(object_id)), name)
    return [(kind, object_id, name) for (kind, object_id), name in found.items()]


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("audit_log_ref")
    connection = op.get_bind()
    for old_type, (object_type, action, _) in _TYPES.items():
        connection.execute(
            sa.text("UPDATE audit_log SET type = :old WHERE type = :new"),
            {"old": old_type, "new": f"{object_type}-{action}"},
        )
    with op.batch_alter_table("audit_log", schema=None, table_kwargs=_AUTOINCREMENT) as batch_op:
        batch_op.drop_index("idx_audit_log_object_type_action")
        batch_op.drop_column("by_identity_name")
        batch_op.drop_column("action")
        batch_op.drop_column("object_type")
