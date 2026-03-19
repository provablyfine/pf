import datetime
import json

from ... import jwk
from .. import db
from ..context import ctx
from . import audit_log


def create(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, valid_after: int, valid_before: int):
    key = jwk.Private.generate(crypto_key_type)
    encrypted_key = ctx.kek.encrypt(json.dumps(key.to_dict()).encode('utf-8'))
    signing_key_id = ctx.db.signing_key.create(type=key_type, serial_number=1, key=encrypted_key, valid_after=valid_after, valid_before=valid_before)
    now = int(datetime.datetime.now().timestamp())
    audit_log.create(
        level=db.AuditLogLevel.INFO,
        at=now,
        type='create-signing-key',
        by_identity_id=None,
        details={
            'key_type': key_type.name,
            'crypto_key_type': crypto_key_type.name,
            'valid_after': valid_after,
            'valid_before': valid_before,
            'signing_key_id': signing_key_id,
        }
    )


def read_all(*args, **kwargs):
    output = []
    keys = ctx.db.signing_key.read_all(*args, **kwargs)
    for key in keys:
        decrypted_key = ctx.kek.decrypt(key.key)
        key_dict = json.loads(decrypted_key.decode('utf-8'))
        output.append(key._replace(key=jwk.Private.from_dict(key_dict)))
    return output


def update(id: int, serial_number: int):
    ctx.db.signing_key.update(serial_number=serial_number).where(id=id)
