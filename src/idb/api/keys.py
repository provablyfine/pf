import datetime
import dataclasses
import json

from .. import jwk
from .. import wa

from . import db
from .context import ctx


@dataclasses.dataclass
class SigningKey:
    key: jwk.Private
    valid_after: int
    valid_before: int


class Keys:
    def __init__(self, type: db.SigningKeyType, staging_period: int):
        self._type = type
        self._staging_period = staging_period
        self._keys = []

    def _refresh(self):
        now = int(datetime.datetime.now().timestamp())
        current = [k for k in self._keys if k.valid_after <= (now-self._staging_period) and k.valid_before > now]
        staged = [k for k in self._keys if k.valid_after > (now-self._staging_period)]
        if len(current) > 0 and len(staged) > 0:
            return current, staged

        keys = ctx.db.signing_key.read_all(
            ctx.db.signing_key.columns.valid_after <= now,
            ctx.db.signing_key.columns.valid_before > now,
            type=self._type,
        )
        self._keys = []
        for key in keys:
            key_dict = ctx.kek.decrypt(key.key).decode('utf-8')
            private_key = jwk.Private.from_dict(json.loads(key_dict))
            self._keys.append(SigningKey(key=private_key, valid_after=key.valid_after, valid_before=key.valid_before))
        current = [k for k in self._keys if k.valid_after <= (now-self._staging_period) and k.valid_before > now]
        staged = [k for k in self._keys if k.valid_after > (now-self._staging_period)]
        if len(current) == 0 or len(staged) == 0:
            raise wa.HTTPException(wa.ProblemResponse(status_code=404, title='Unable to find signing keys'))
        return current, staged

    @property
    def current(self) -> tuple[SigningKey]:
        current, staged = self._refresh()
        return tuple(current)

    @property
    def staged(self) -> tuple[SigningKey]:
        current, staged = self._refresh()
        return tuple(staged)
