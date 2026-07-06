import dataclasses
import time
import typing

import jwt

from ... import jwk
from ..context import ctx
from . import audit_log, identity, oidc_key


class Unset:
    pass


_UNSET = Unset()


@dataclasses.dataclass(frozen=True)
class Bastion:
    id: int
    tag_id_list: list[int]
    url: str
    ssh_proxy_jump: str | None = None
    created_at: int | None = None
    created_by_id: int | None = None


def create(
    url: str,
    ssh_proxy_jump: str | None | Unset = _UNSET,
    tag_id_list: list[int] | None | Unset = _UNSET,
) -> int:
    now = int(time.time())
    bastion_id = ctx.app_db.bastion.create(
        url=url,
        ssh_proxy_jump=None if ssh_proxy_jump is _UNSET else ssh_proxy_jump,
        tag_id_list=[] if tag_id_list is _UNSET else tag_id_list,
        created_at=now,
        created_by_id=ctx.identity_id,
    )
    assert bastion_id is not None
    audit_log.create(
        "bastion-create",
        id=bastion_id,
        url=url,
        ssh_proxy_jump=ssh_proxy_jump,
        tag_id_list=tag_id_list,
    )
    return bastion_id


def read_one(**kwargs: typing.Any) -> Bastion | None:
    bastions = read_all(**kwargs)
    if len(bastions) == 0:
        return None
    return bastions[0]


def read_all(**kwargs: typing.Any) -> list[Bastion]:
    query: dict[str, typing.Any] = {}
    if "id" in kwargs:
        ids: int | list[int] = kwargs["id"]
        if isinstance(ids, int):
            ids = [ids]
        query["id"] = ids
    if "created_by_id" in kwargs:
        query["created_by_id"] = kwargs["created_by_id"]

    bastions = ctx.app_db.bastion.read_all(**query)
    return [
        Bastion(
            id=b.id,
            url=b.url,
            ssh_proxy_jump=b.ssh_proxy_jump,
            tag_id_list=b.tag_id_list,
            created_at=b.created_at,
            created_by_id=b.created_by_id,
        )
        for b in bastions
    ]


def update(
    id: int,
    url: str | None = None,
    ssh_proxy_jump: str | None = None,
    tag_id_list: list[int] | None = None,
) -> None:
    update_fields: dict[str, typing.Any] = {}
    if url is not None:
        update_fields["url"] = url
    if ssh_proxy_jump is not None:
        update_fields["ssh_proxy_jump"] = ssh_proxy_jump
    if tag_id_list is not None:
        update_fields["tag_id_list"] = tag_id_list

    if len(update_fields) > 0:
        audit_log.create(
            "bastion-update",
            id=id,
            **update_fields,
        )
        ctx.app_db.bastion.update(**update_fields).where(id=id)


def delete(id: int) -> None:
    audit_log.create("bastion-delete", id=id)
    ctx.app_db.bastion.delete(id=id)


def read_matching() -> list[Bastion]:
    caller = identity.read_one(id=ctx.identity_id)
    if caller is None:
        return []

    all_bastions = read_all()
    matching: list[Bastion] = []
    for bastion in all_bastions:
        if len(bastion.tag_id_list) == 0:
            matching.append(bastion)
        else:
            for tag_id in bastion.tag_id_list:
                if tag_id in caller.tag_id_list:
                    matching.append(bastion)
                    break
    return matching


def generate_token(hostname: str) -> str:
    private_key = oidc_key.get_private_key()
    assert private_key.type == jwk.KeyType.ED25519
    self_identity = identity.read_one(id=ctx.identity_id)
    assert self_identity is not None
    iss = f"{ctx.config.base_url}/pf/t/{ctx.tenant_name}/public/oidc"
    now = int(time.time())
    claims = {
        "sub": str(self_identity.id),
        "iss": iss,
        "aud": hostname,
        "iat": now,
        "exp": now + 60,
        "name": self_identity.name,
        "tenant_id": ctx.tenant_id,
    }
    return jwt.encode(claims, private_key.to_crypto(), algorithm="EdDSA", headers={"kid": private_key.thumbprint()})
