import dataclasses
import json
import time
import typing

from .. import app_db
from ..context import ctx
from . import audit_log


@dataclasses.dataclass(frozen=True)
class AuthConfig:
    id: int
    name: str
    client_type: str
    description: str
    created_at: int
    is_enabled: bool
    type: str
    config: dict[str, typing.Any]


def _from_db(row: app_db.AuthRow) -> AuthConfig:
    return AuthConfig(
        id=row.id,
        name=row.name,
        client_type=row.client_type,
        description=row.description,
        created_at=row.created_at,
        is_enabled=row.is_enabled,
        type=row.type,
        config=json.loads(ctx.kek.decrypt(row.config)),
    )


def create(name: str, client_type: str, description: str, type: str, config: dict[str, typing.Any]) -> int:
    now = int(time.time())
    auth_id = ctx.app_db.auth.create(
        name=name,
        client_type=client_type,
        description=description,
        created_at=now,
        is_enabled=True,
        type=type,
        config=ctx.kek.encrypt(json.dumps(config).encode()),
    )
    assert auth_id is not None
    audit_log.create("auth-create", id=auth_id, name=name)
    return auth_id


def read_all(**kwargs: typing.Any) -> list[AuthConfig]:
    rows = ctx.app_db.auth.read_all(**kwargs)
    return [_from_db(r) for r in rows]


def read_one(**kwargs: typing.Any) -> AuthConfig | None:
    rows = read_all(**kwargs)
    if len(rows) == 0:
        return None
    return rows[0]


def update(id: int, **fields: typing.Any) -> None:
    allowed = {"name", "description", "is_enabled", "config"}
    update_fields = {k: v for k, v in fields.items() if k in allowed and v is not None}
    audit_fields = {k: v for k, v in update_fields.items() if k != "config"}
    if "config" in update_fields:
        update_fields["config"] = ctx.kek.encrypt(json.dumps(update_fields["config"]).encode())
    if update_fields:
        ctx.app_db.auth.update(**update_fields).where(id=id)
    audit_log.create("auth-update", id=id, **audit_fields)


def delete(id: int) -> None:
    ctx.app_db.auth.delete(id=id)
    audit_log.create("auth-delete", id=id)
