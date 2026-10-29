"""Every kind of entry that the audit log can hold.

An entry is about one object type and records one action.
The joined `object_type-action` string is the entry's `type`.

Each constant here is the only way for the server to write an entry.
Readers can list the pairs with `all_types`.
"""

import dataclasses
import enum

from .. import app_db


@enum.unique
class ObjectType(enum.StrEnum):
    """What an entry is about. It is also the kind of every object in `refs`."""

    ACCOUNT_KEY = "account-key"
    AUTH = "auth"
    BASTION = "bastion"
    BOUNDARY = "boundary"
    CERTIFICATE = "certificate"
    IDENTITY = "identity"
    IDENTITY_INVITATION = "identity-invitation"
    LIVE_SESSION = "live-session"
    PUBLIC_KEY = "public-key"
    ROLE = "role"
    SESSION = "session"
    SIGNING_KEY = "signing-key"
    TAG = "tag"
    TENANT = "tenant"
    # An entry from an older version whose type is no longer written.
    UNKNOWN = "unknown"


@enum.unique
class Action(enum.StrEnum):
    """What happened to the object."""

    ACCEPTED = "accepted"
    ADD_MEMBERS = "add-members"
    ADD_TAGS = "add-tags"
    CREATE = "create"
    CREATE_HOST = "create-host"
    CREATE_USER = "create-user"
    DELETE = "delete"
    DELETE_REFUSED = "delete-refused"
    DENYLISTED = "denylisted"
    LOGIN = "login"
    LOGOUT = "logout"
    REJECTED = "rejected"
    REMOVE_MEMBERS = "remove-members"
    PURGE_EXPIRED = "purge-expired"
    REMOVE_TAGS = "remove-tags"
    SET = "set"
    SET_ROLE = "set-role"
    TERMINATE = "terminate"
    UPDATE = "update"
    UPDATE_CEILING_LIST = "update-ceiling-list"
    UPDATE_DENIED_LIST = "update-denied-list"
    UPDATE_DESCRIPTION = "update-description"
    UPDATE_GRANT_LIST = "update-grant-list"
    UPDATE_NAME = "update-name"
    UPDATE_SERIAL = "update-serial"
    UPDATE_UNIX_USERNAME = "update-unix-username"
    # Entries that older versions wrote, and that are no longer written.
    DELETE_CASCADE = "delete-cascade"
    UPDATE_UNIX_GID = "update-unix-gid"
    UPDATE_UNIX_UID = "update-unix-uid"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class AuditType:
    object_type: ObjectType
    action: Action
    level: app_db.AuditLogLevel = app_db.AuditLogLevel.INFO
    # The key of `details` that holds the id of the object the entry is about.
    target_key: str | None = "id"
    # The entry gives the object the name it carries in `details`. Creating and renaming do.
    # An update that may or may not rename carries the name only when it changes it.
    names_object: bool = False

    @property
    def type(self) -> str:
        return f"{self.object_type}-{self.action}"


IDENTITY_CREATE = AuditType(ObjectType.IDENTITY, Action.CREATE, names_object=True)
IDENTITY_DELETE = AuditType(ObjectType.IDENTITY, Action.DELETE)
IDENTITY_UPDATE_NAME = AuditType(ObjectType.IDENTITY, Action.UPDATE_NAME, names_object=True)
IDENTITY_UPDATE_UNIX_USERNAME = AuditType(ObjectType.IDENTITY, Action.UPDATE_UNIX_USERNAME)
IDENTITY_ADD_TAGS = AuditType(ObjectType.IDENTITY, Action.ADD_TAGS)
IDENTITY_REMOVE_TAGS = AuditType(ObjectType.IDENTITY, Action.REMOVE_TAGS)
IDENTITY_DELETE_REFUSED = AuditType(
    ObjectType.IDENTITY, Action.DELETE_REFUSED, app_db.AuditLogLevel.WARNING, target_key="identity_id"
)

IDENTITY_INVITATION_CREATE = AuditType(ObjectType.IDENTITY_INVITATION, Action.CREATE)
IDENTITY_INVITATION_ACCEPTED = AuditType(ObjectType.IDENTITY_INVITATION, Action.ACCEPTED)
IDENTITY_INVITATION_REJECTED = AuditType(ObjectType.IDENTITY_INVITATION, Action.REJECTED, app_db.AuditLogLevel.WARNING)

ROLE_CREATE = AuditType(ObjectType.ROLE, Action.CREATE, names_object=True)
ROLE_DELETE = AuditType(ObjectType.ROLE, Action.DELETE)
ROLE_UPDATE_NAME = AuditType(ObjectType.ROLE, Action.UPDATE_NAME, names_object=True)
ROLE_UPDATE_DESCRIPTION = AuditType(ObjectType.ROLE, Action.UPDATE_DESCRIPTION)
ROLE_UPDATE_GRANT_LIST = AuditType(ObjectType.ROLE, Action.UPDATE_GRANT_LIST)
ROLE_ADD_MEMBERS = AuditType(ObjectType.ROLE, Action.ADD_MEMBERS)
ROLE_REMOVE_MEMBERS = AuditType(ObjectType.ROLE, Action.REMOVE_MEMBERS)

BOUNDARY_CREATE = AuditType(ObjectType.BOUNDARY, Action.CREATE, names_object=True)
BOUNDARY_DELETE = AuditType(ObjectType.BOUNDARY, Action.DELETE)
BOUNDARY_UPDATE_NAME = AuditType(ObjectType.BOUNDARY, Action.UPDATE_NAME, names_object=True)
BOUNDARY_UPDATE_DESCRIPTION = AuditType(ObjectType.BOUNDARY, Action.UPDATE_DESCRIPTION)
BOUNDARY_UPDATE_CEILING_LIST = AuditType(ObjectType.BOUNDARY, Action.UPDATE_CEILING_LIST)
BOUNDARY_UPDATE_DENIED_LIST = AuditType(ObjectType.BOUNDARY, Action.UPDATE_DENIED_LIST)

TAG_CREATE = AuditType(ObjectType.TAG, Action.CREATE, names_object=True)
TAG_DELETE = AuditType(ObjectType.TAG, Action.DELETE)

BASTION_CREATE = AuditType(ObjectType.BASTION, Action.CREATE, names_object=True)
BASTION_UPDATE = AuditType(ObjectType.BASTION, Action.UPDATE, names_object=True)
BASTION_DELETE = AuditType(ObjectType.BASTION, Action.DELETE)

AUTH_CREATE = AuditType(ObjectType.AUTH, Action.CREATE, names_object=True)
AUTH_UPDATE = AuditType(ObjectType.AUTH, Action.UPDATE, names_object=True)
AUTH_DELETE = AuditType(ObjectType.AUTH, Action.DELETE)

SESSION_LOGIN = AuditType(ObjectType.SESSION, Action.LOGIN, target_key="session_key_id")
SESSION_LOGOUT = AuditType(ObjectType.SESSION, Action.LOGOUT, target_key="session_key_id")
SESSION_SET_ROLE = AuditType(ObjectType.SESSION, Action.SET_ROLE, target_key="session_key_id")
SESSION_REJECTED = AuditType(
    ObjectType.SESSION, Action.REJECTED, app_db.AuditLogLevel.WARNING, target_key="session_key_id"
)

ACCOUNT_KEY_REJECTED = AuditType(
    ObjectType.ACCOUNT_KEY, Action.REJECTED, app_db.AuditLogLevel.WARNING, target_key="account_key_id"
)

LIVE_SESSION_TERMINATE = AuditType(ObjectType.LIVE_SESSION, Action.TERMINATE, target_key="live_session_id")

SIGNING_KEY_CREATE = AuditType(ObjectType.SIGNING_KEY, Action.CREATE, target_key="signing_key_id")
SIGNING_KEY_UPDATE_SERIAL = AuditType(ObjectType.SIGNING_KEY, Action.UPDATE_SERIAL)

CERTIFICATE_CREATE_USER = AuditType(ObjectType.CERTIFICATE, Action.CREATE_USER, target_key=None)
CERTIFICATE_CREATE_HOST = AuditType(ObjectType.CERTIFICATE, Action.CREATE_HOST, target_key=None)

PUBLIC_KEY_DENYLISTED = AuditType(
    ObjectType.PUBLIC_KEY, Action.DENYLISTED, app_db.AuditLogLevel.WARNING, target_key="public_key_id"
)
PUBLIC_KEY_REJECTED = AuditType(
    ObjectType.PUBLIC_KEY, Action.REJECTED, app_db.AuditLogLevel.WARNING, target_key="public_key_id"
)

# A change to a tenant: its display name, whether it is enabled, or one of its retention values.
# It is written in the tenant that changed and in the tenant of the caller when they differ.
# It is never purged, because it holds the retention changes. A tenant changes rarely, so it stays small.
TENANT_UPDATE = AuditType(ObjectType.TENANT, Action.UPDATE, target_key=None)

# What a purge deleted. The details name no one but the actor.
TENANT_PURGE_EXPIRED = AuditType(ObjectType.TENANT, Action.PURGE_EXPIRED, target_key=None)


@enum.unique
class RetentionClass(enum.Enum):
    """Which retention period applies to an entry."""

    # Changes to the configuration. Anything not listed below.
    AUDIT = "audit"
    # Logins, rejections and connections.
    ACTIVITY = "activity"
    # The proof that retention ran, and the changes to the tenant. Never purged.
    # They name the identity that made the change. They hold no other data about a person.
    EXEMPT = "exempt"


ACTIVITY_TYPES = (
    SESSION_LOGIN,
    SESSION_LOGOUT,
    SESSION_SET_ROLE,
    SESSION_REJECTED,
    ACCOUNT_KEY_REJECTED,
    PUBLIC_KEY_REJECTED,
    LIVE_SESSION_TERMINATE,
    CERTIFICATE_CREATE_USER,
    CERTIFICATE_CREATE_HOST,
)

EXEMPT_TYPES = (TENANT_UPDATE, TENANT_PURGE_EXPIRED)


def retention_class(entry_type: str) -> RetentionClass:
    """The class of an entry, from its joined `type`. A type that is not listed is `AUDIT`."""
    if entry_type in {t.type for t in EXEMPT_TYPES}:
        return RetentionClass.EXEMPT
    if entry_type in {t.type for t in ACTIVITY_TYPES}:
        return RetentionClass.ACTIVITY
    return RetentionClass.AUDIT


def all_types() -> list[AuditType]:
    """Every registered type, in declaration order."""
    return [v for v in globals().values() if isinstance(v, AuditType)]


def actions_by_object_type() -> dict[ObjectType, list[Action]]:
    """The actions that the server writes for each object type, in declaration order."""
    result: dict[ObjectType, list[Action]] = {}
    for audit_type in all_types():
        result.setdefault(audit_type.object_type, []).append(audit_type.action)
    return result
