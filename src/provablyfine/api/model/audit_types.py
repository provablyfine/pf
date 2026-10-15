"""Every kind of entry that the audit log can hold.

An entry is about one object type and records one action.
The joined `object_type-action` string is the entry's `type`.

Each constant here is the only way for the server to write an entry.
Readers can list the pairs with `all_types`.
"""

import dataclasses

INFO = 1
WARNING = 2


@dataclasses.dataclass(frozen=True)
class AuditType:
    object_type: str
    action: str
    level: int = INFO
    # The key of `details` that holds the id of the object the entry is about.
    target_key: str | None = "id"

    @property
    def type(self) -> str:
        return f"{self.object_type}-{self.action}"


IDENTITY_CREATE = AuditType("identity", "create")
IDENTITY_DELETE = AuditType("identity", "delete")
IDENTITY_UPDATE_NAME = AuditType("identity", "update-name")
IDENTITY_UPDATE_UNIX_USERNAME = AuditType("identity", "update-unix-username")
IDENTITY_ADD_TAGS = AuditType("identity", "add-tags")
IDENTITY_REMOVE_TAGS = AuditType("identity", "remove-tags")
IDENTITY_DELETE_REFUSED = AuditType("identity", "delete-refused", WARNING, target_key="identity_id")

IDENTITY_INVITATION_CREATE = AuditType("identity-invitation", "create")
IDENTITY_INVITATION_ACCEPTED = AuditType("identity-invitation", "accepted")
IDENTITY_INVITATION_REJECTED = AuditType("identity-invitation", "rejected", WARNING)

ROLE_CREATE = AuditType("role", "create")
ROLE_DELETE = AuditType("role", "delete")
ROLE_UPDATE_NAME = AuditType("role", "update-name")
ROLE_UPDATE_DESCRIPTION = AuditType("role", "update-description")
ROLE_UPDATE_GRANT_LIST = AuditType("role", "update-grant-list")
ROLE_ADD_MEMBERS = AuditType("role", "add-members")
ROLE_REMOVE_MEMBERS = AuditType("role", "remove-members")

BOUNDARY_CREATE = AuditType("boundary", "create")
BOUNDARY_DELETE = AuditType("boundary", "delete")
BOUNDARY_UPDATE_NAME = AuditType("boundary", "update-name")
BOUNDARY_UPDATE_DESCRIPTION = AuditType("boundary", "update-description")
BOUNDARY_UPDATE_CEILING_LIST = AuditType("boundary", "update-ceiling-list")
BOUNDARY_UPDATE_DENIED_LIST = AuditType("boundary", "update-denied-list")

TAG_CREATE = AuditType("tag", "create")
TAG_DELETE = AuditType("tag", "delete")

BASTION_CREATE = AuditType("bastion", "create")
BASTION_UPDATE = AuditType("bastion", "update")
BASTION_DELETE = AuditType("bastion", "delete")

AUTH_CREATE = AuditType("auth", "create")
AUTH_UPDATE = AuditType("auth", "update")
AUTH_DELETE = AuditType("auth", "delete")

SESSION_LOGIN = AuditType("session", "login", target_key="session_key_id")
SESSION_LOGOUT = AuditType("session", "logout", target_key="session_key_id")
SESSION_SET_ROLE = AuditType("session", "set-role", target_key="session_key_id")
SESSION_REJECTED = AuditType("session", "rejected", WARNING, target_key="session_key_id")

ACCOUNT_KEY_REJECTED = AuditType("account-key", "rejected", WARNING, target_key="account_key_id")

LIVE_SESSION_TERMINATE = AuditType("live-session", "terminate", target_key="live_session_id")

SIGNING_KEY_CREATE = AuditType("signing-key", "create", target_key="signing_key_id")
SIGNING_KEY_UPDATE_SERIAL = AuditType("signing-key", "update-serial")

CERTIFICATE_CREATE_USER = AuditType("certificate", "create-user", target_key=None)
CERTIFICATE_CREATE_HOST = AuditType("certificate", "create-host", target_key=None)

PUBLIC_KEY_DENYLISTED = AuditType("public-key", "denylisted", WARNING, target_key="public_key_id")
PUBLIC_KEY_REJECTED = AuditType("public-key", "rejected", WARNING, target_key="public_key_id")


def all_types() -> list[AuditType]:
    """Every registered type, in declaration order."""
    return [v for v in globals().values() if isinstance(v, AuditType)]
