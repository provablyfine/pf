import json
import typing

from ... import jwk
from .. import app_db, responses
from ..context import ctx
from . import audit_log


def create(key_type: app_db.SigningKeyType, crypto_key_type: jwk.KeyType, valid_after: int, valid_before: int):
    key = jwk.Private.generate(crypto_key_type)
    encrypted_key = ctx.kek.encrypt(json.dumps(key.to_dict()).encode("utf-8"))
    signing_key_id = ctx.app_db.signing_key.create(
        type=key_type, serial_number=1, key=encrypted_key, valid_after=valid_after, valid_before=valid_before
    )
    audit_log.create(
        "signing-key-create",
        key_type=key_type.name,
        crypto_key_type=crypto_key_type.name,
        valid_after=valid_after,
        valid_before=valid_before,
        signing_key_id=signing_key_id,
    )


def read_all(*args: typing.Any, **kwargs: typing.Any) -> list[typing.Any]:
    output: list[typing.Any] = []
    keys = ctx.app_db.signing_key.read_all(*args, **kwargs)
    for key in keys:
        decrypted_key = ctx.kek.decrypt(key.key)
        key_dict = json.loads(decrypted_key.decode("utf-8"))
        output.append(key._replace(key=jwk.Private.from_dict(key_dict)))
    return output


_SERIAL_ATTEMPTS = 5


def allocate_serial_numbers(id: int, count: int) -> int:
    """Reserve `count` consecutive serial numbers of a signing key and return the first one.

    The counter moves forward with a conditional update. If another request moved it after we read it,
    the update changes no row and we read again. A serial number is never handed out twice.
    """
    for _ in range(_SERIAL_ATTEMPTS):
        row = ctx.app_db.signing_key.read_one(id=id)
        assert row is not None
        first = row.serial_number
        if count == 0:
            return first
        if ctx.app_db.signing_key.update(serial_number=first + count).where(id=id, serial_number=first) == 1:
            audit_log.create("signing-key-update-serial", id=id, serial_number=first + count)
            return first
    raise responses.ProblemHTTPException(
        responses.problem_response(status_code=409, title="Unable to reserve serial numbers, try again")
    )
