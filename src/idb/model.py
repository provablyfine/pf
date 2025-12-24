import secrets
import datetime
import time

from . import db
from . import config
from . import base64url
from . import jwk


class IdentityInvitation:
    def __init__(self, id, key: bytes, identity_id, is_accepted, created_at, expires_at):
        self._id = id
        self._key = key
        self._identity_id = identity_id
        self._is_accepted = is_accepted
        self._created_at = created_at
        self._expires_at = expires_at
        self._audit_log = []

    @property
    def audit_log(self):
        return self._audit_log

    @property
    def id(self):
        return self._id

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def identity_id(self):
        return self._identity_id

    @property
    def is_expired(self):
        now = int(time.time())
        return now >= self._expires_at

    @property
    def is_accepted(self):
        return self._is_accepted

    def accept(self):
        assert not self._is_accepted
        self._is_accepted = True
        self._audit_log.append(AuditLog.create('identity-invitation-accepted', id=self._id, identity=self._identity_id))

    @staticmethod
    def create(identity_id, expiration_delay_s):
        key = jwk.Symmetric.generate()
        id = key.thumbprint()
        now = int(time.time())
        expires_at = now + expiration_delay_s
        ii = IdentityInvitation(id=id, key=key.to_bytes(), identity_id=identity_id, is_accepted=False, created_at=now, expires_at=expires_at)
        ii._audit_log.append(AuditLog.create('identity-invitation-create', id=id, identity=identity_id, expires_at=expires_at))
        return ii

    @staticmethod
    def from_id(dao, id, kek):
        invitation = dao.identity_invitation.read_one(id=id)
        if invitation is None:
            return None
        return IdentityInvitation.deserialize(invitation.identity_invitation, kek)

    def serialize(self, kek):
        return {
            'id': self._id,
            'key': kek.encrypt(self._key).hex(),
            'identity_id': self._identity_id,
            'is_accepted': self._is_accepted,
            'created_at': self._created_at,
            'expires_at': self._expires_at,
        }

    @staticmethod
    def deserialize(data, kek):
        key = kek.decrypt(bytes.fromhex(data['key']))
        ii = IdentityInvitation(
            id=data['id'],
            key=key,
            identity_id=data['identity_id'],
            is_accepted=data['is_accepted'],
            created_at=data['created_at'],
            expires_at=data['expires_at']
        )
        return ii

    def format(self):
        return {
            'key': base64url.encode(self._key)
        }


class Identity:
    def __init__(self, id, name, boundary_id):
        self._id = id
        self._name = name
        self._boundary_id = boundary_id
        self._audit_log = []

    @property
    def audit_log(self):
        return self._audit_log

    @staticmethod
    def create(name, boundary_id):
        id = secrets.token_hex(4)
        identity = Identity(id=id, name=name, boundary_id=boundary_id)
        identity._audit_log.append(AuditLog.create('identity-create', id=id, name=name, boundary_id=boundary_id))
        return identity

    @staticmethod
    async def from_id(dao, id):
        db = await dao.identity.read_one(id=id)
        return Identity.deserialize(db.identity)

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def boundary_id(self):
        return self._boundary_id

    def serialize(self):
        return {
            'id': self._id,
            'name': self._name,
            'boundary_id': self._boundary_id,
        }

    @staticmethod
    def deserialize(data):
        return Identity(data['id'], data['name'], data['boundary_id'])

    def format(self):
        return {
            'id': self._id,
            'name': self._name,
            'boundary_id': self._boundary_id,
        }


class Role:
    def __init__(self, id, name, description, permissions):
        self._id = id
        self._name = name
        self._description = description
        self._permissions = permissions
        self._audit_log = []

    @property
    def audit_log(self):
        return self._audit_log

    @staticmethod
    def create(name, description):
        id = secrets.token_hex(4)
        role = Role(id=id, name=name, description=description, permissions=[])
        role._audit_log.append(AuditLog.create('role-create', id=id, name=name, description=description))
        return role

    @staticmethod
    async def from_ids(dao, ids):
        db = await dao.role.read_all(id=ids)
        roles = [Role.deserialize(r.role) for r in db]
        return roles

    def set_name(self, name):
        self._name = name
        self._audit_log.append(AuditLog.create('role-update', id=id, name=name))

    def set_description(self, description):
        self._description = description
        self._audit_log.append(AuditLog.create('role-update', id=id, description=description))

    def add_permission(self, permission):
        if permission in self._permissions:
            return
        self._permissions.append(permission)
        self._audit_log.append(AuditLog.create('role-add-permission', id=self._id, permission=permission))

    def del_permission(self, permission):
        try:
            i = self._permissions.find(permission)
        except ValueError:
            return
        del self._permissions[i]
        self._audit_log.append(AuditLog.create('role-del-permission', id=self._id, permission=permission))

    @property
    def id(self):
        return self._id

    @property
    def permissions(self):
        return self._permissions

    def serialize(self):
        return {
            'id': self._id,
            'name': self._name,
            'description': self._description,
            'permissions': self._permissions
        }

    @staticmethod
    def deserialize(data):
        return Role(id=data['id'], name=data['name'], description=data['description'], permissions=data['permissions'])

    def format(self):
        return {
            'id': self._id,
            'name': self._name,
            'description': self._description,
            'permissions': self._permissions
        }

class AuditLog:
    def __init__(self, type, details):
        self._type = type
        self._details = details

    @staticmethod
    def create(type, **kwargs):
        return AuditLog(type, kwargs)

    @staticmethod
    def create_role_add_identity(role_id, to_whom):
        return AuditLog(type='role-add-identity', details=dict(role_id=role_id, to_whom=to_whom))

    @staticmethod
    def create_role_del_identity(role_id, to_whom):
        return AuditLog(type='role-del-identity', details=dict(role_id=role_id, to_whom=to_whom))

    @staticmethod
    def create_role_add_group(role_id, to_whom):
        return AuditLog(type='role-add-group', details=dict(role_id=role_id, to_whom=to_whom))

    @staticmethod
    def create_role_del_group(role_id, to_whom):
        return AuditLog(type='role-del-group', details=dict(role_id=role_id, to_whom=to_whom))

    def serialize(self, by):
        return {
            'type': self._type,
            'at': int(time.time()),
            'by': by,
            'details': self._details
        }

class Boundary:
    def __init__(self, id, name, description, denies):
        self._id = id
        self._name = name
        self._description = description
        self._denies = denies
        self._audit_log = []

    @property
    def id(self):
        return self._id

    @property
    def denies(self):
        return self._denies

    @property
    def audit_log(self):
        return self._audit_log

    def add_deny(self, permission):
        self._denies.append(permission)
        self._audit_log.append(AuditLog.create('boundary-add-deny', id=self._id, permission=permission))

    def del_deny(self, permission):
        try:
            i = self._denies.index(permission)
        except ValueError:
            return
        del self._denies[i]
        self._audit_log.append(AuditLog.create('boundary-del-deny', id=self._id, permission=permission))

    @staticmethod
    def create(name, description):
        id = secrets.token_hex(4)
        boundary = Boundary(id=id, name=name, description=description, denies=[])
        boundary._audit_log.append(AuditLog.create('boundary-create', id=id, name=name, description=description))
        return boundary

    @staticmethod
    async def from_id(dao, id):
        db = await dao.boundary.read_one(id=id)
        return Boundary.deserialize(db.boundary)

    def serialize(self):
        return {
            'id': self._id,
            'name': self._name,
            'description': self._description,
            'denies': self._denies,
        }

    @staticmethod
    def deserialize(data):
        return Boundary(**data)


    def format(self):
        return self.serialize()
