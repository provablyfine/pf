import datetime
import json

from ... import jwk
from ..context import ctx


def create(valid_after: int, valid_before: int):
    key = jwk.Private.generate(jwk.KeyType.ED25519)
    encrypted_key = ctx.kek.encrypt(json.dumps(key.to_dict()).encode("utf-8"))
    now = int(datetime.datetime.now().timestamp())
    key_id = ctx.db.oidc_key.create(
        private_key=encrypted_key,
        public_key=key.public().to_dict(),
        valid_after=valid_after,
        valid_before=valid_before,
        created_at=now,
    )
    assert key_id is not None
    return key_id


def get_public_keys() -> list[jwk.Public]:
    now = int(datetime.datetime.now().timestamp())
    grace_period = ctx.config.oidc_key_grace_period
    keys = ctx.db.oidc_key.read_all(ctx.db.oidc_key.columns.valid_after <= now, ctx.db.oidc_key.columns.valid_before + grace_period > now)
    public_keys = [jwk.Public.from_dict(k.public_key) for k in keys]
    return public_keys



def get_private_key() -> jwk.Private:
    now = int(datetime.datetime.now().timestamp())
    active_keys = ctx.db.oidc_key.read_all(ctx.db.oidc_key.columns.valid_after <= now, ctx.db.oidc_key.columns.valid_before > now)
    if len(active_keys) == 0:
        create(now, now + ctx.config.oidc_key_rotation_period)
        active_keys = ctx.db.oidc_key.read_all(ctx.db.oidc_key.columns.valid_after <= now, ctx.db.oidc_key.columns.valid_before > now)

    active_keys.sort(key=lambda k: k.created_at, reverse=True)
    key_row = active_keys[0]
    decrypted = ctx.kek.decrypt(key_row.private_key)
    return jwk.Private.from_dict(json.loads(decrypted.decode("utf-8")))
