import time
import dataclasses

from ... import jwk
from ..context import ctx

from . import audit_log

@dataclasses.dataclass
class IdentityInvitationKey:
    id: str
    key: jwk.Symmetric
    identity_id: int
    created_at: int
    expires_at: int
    is_revoked: bool
    is_accepted: bool
    revoked_at: int|None = None
    accepted_at: int|None = None
    accepted_public_key_id: str|None = None


def create(identity_id: int, expiration_delay_s: int) -> str:
    key = jwk.Symmetric.generate()
    id = key.thumbprint()
    now = int(time.time())
    expires_at = now + expiration_delay_s
    ctx.db.identity_invitation_key.create(
        id=id,
        key=ctx.kek.encrypt(key.to_bytes()),
        identity_id=identity_id,
        created_at=now,
        revoked_at=None,
        accepted_at=None,
        expires_at=now+expiration_delay_s,
        is_revoked=False,
        is_accepted=False,
    )
    audit_log.create('identity-invitation-create', id=id, identity_id=identity_id, expires_at=expires_at)
    return id


def accept(id: str, public_key_id):
    now = int(time.time())
    invitation = ctx.db.identity_invitation_key.read_one(id=id)
    assert invitation is not None
    assert not invitation.is_accepted
    assert not invitation.is_revoked
    assert invitation.expires_at > now
    ctx.db.identity_invitation_key.update(
        is_accepted=True,
        accepted_at=now,
        accepted_public_key_id=public_key_id,
    ).where(id=invitation.id)
    audit_log.create('identity-invitation-accepted', id=invitation.id, identity_id=invitation.identity_id)


def read(id: str) -> IdentityInvitationKey|None:
    invitation = ctx.db.identity_invitation_key.read_one(id=id)
    if invitation is None:
        return None
    key =  jwk.Symmetric.from_bytes(ctx.kek.decrypt(invitation.key))
    return IdentityInvitationKey(
        id=invitation.id,
        key=key,
        identity_id=invitation.identity_id,
        created_at=invitation.created_at,
        expires_at=invitation.expires_at,
        is_revoked=invitation.is_revoked,
        is_accepted=invitation.is_accepted,
        revoked_at=invitation.revoked_at,
        accepted_at=invitation.accepted_at,
        accepted_public_key_id=invitation.accepted_public_key_id,
    )
