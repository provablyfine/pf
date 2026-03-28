import dataclasses
import time

from ..context import ctx
from . import audit_log


@dataclasses.dataclass(frozen=True)
class AuthConfig:
    id: int
    name: str
    description: str
    tag_id_list: list[int]
    created_at: int
    is_enabled: bool
    type: str  # "http_sig" | "oidc"
    config: dict  # type-specific; oidc: {"issuer": "...", "client_id": "..."}


def _from_db(row) -> AuthConfig:
    return AuthConfig(
        id=row.id,
        name=row.name,
        description=row.description,
        tag_id_list=row.tag_id_list,
        created_at=row.created_at,
        is_enabled=row.is_enabled,
        type=row.type,
        config=row.config,
    )


def create(name: str, description: str, tag_id_list: list[int], type: str, config: dict) -> int:
    now = int(time.time())
    auth_id = ctx.db.auth.create(
        name=name,
        description=description,
        tag_id_list=tag_id_list,
        created_at=now,
        is_enabled=True,
        type=type,
        config=config,
    )
    assert auth_id is not None
    audit_log.create("auth-create", id=auth_id, name=name)
    return auth_id


def read_all(**kwargs) -> list[AuthConfig]:
    rows = ctx.db.auth.read_all(**kwargs)
    return [_from_db(r) for r in rows]


def read_one(**kwargs) -> AuthConfig | None:
    rows = read_all(**kwargs)
    if len(rows) == 0:
        return None
    return rows[0]


def update(id: int, **fields) -> None:
    allowed = {"name", "description", "tag_id_list", "is_enabled", "config"}
    update_fields = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if update_fields:
        ctx.db.auth.update(**update_fields).where(id=id)
    audit_log.create("auth-update", id=id, **update_fields)


def delete(id: int) -> None:
    ctx.db.auth.delete(id=id)
    audit_log.create("auth-delete", id=id)
