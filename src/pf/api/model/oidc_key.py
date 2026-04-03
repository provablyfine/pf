import datetime
import json
import uuid

from ... import jwk
from ..context import ctx


def create(algorithm: str, valid_after: int, valid_before: int):
    key = jwk.Private.generate(jwk.KeyType.ED25519)
    encrypted_key = ctx.kek.encrypt(json.dumps(key.to_dict()).encode("utf-8"))
    public_key_jwk = key.public().to_dict()
    public_key_jwk["alg"] = algorithm
    public_key_jwk["kid"] = str(uuid.uuid4())
    now = int(datetime.datetime.now().timestamp())
    key_id = ctx.db.oidc_key.create(
        key_id=public_key_jwk["kid"],
        algorithm=algorithm,
        private_key=encrypted_key,
        public_key=json.dumps(public_key_jwk),
        valid_after=valid_after,
        valid_before=valid_before,
        created_at=now,
    )
    assert key_id is not None


def _ensure_active_keys() -> None:
    now = int(datetime.datetime.now().timestamp())
    staging_period = ctx.config.oidc_key_staging_period
    rotation_period = ctx.config.oidc_key_rotation_period

    keys = ctx.db.oidc_key.read_all()
    active_keys = [k for k in keys if k.valid_after <= now + staging_period and k.valid_before > now]

    if not active_keys or any(k.valid_before < now + staging_period for k in active_keys):
        valid_after = now + staging_period
        valid_before = now + rotation_period + staging_period
        create("EdDSA", valid_after, valid_before)


def get_jwks() -> dict:
    _ensure_active_keys()
    now = int(datetime.datetime.now().timestamp())
    staging_period = ctx.config.oidc_key_staging_period

    keys = ctx.db.oidc_key.read_all()
    active_keys = [
        json.loads(k.public_key) for k in keys if k.valid_after <= now + staging_period and k.valid_before > now
    ]

    return {"keys": active_keys}
