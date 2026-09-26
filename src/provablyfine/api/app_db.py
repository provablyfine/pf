"""Application database schema and typed DAO.

Tables are defined as NamedTuple classes (single source of truth for column types)
and generated via make_table(). The AppDb typed DAO exposes each table with its
row type visible to pyright.
"""

import enum
import typing

import sqlalchemy

from . import orm

# Type variable for generic Table
T = typing.TypeVar("T")


@enum.unique
class AuditLogLevel(enum.IntEnum):
    INFO = 1
    WARNING = 2


@enum.unique
class SigningKeyType(enum.IntEnum):
    HOST = 1
    USER = 2


# Database metadata
metadata = sqlalchemy.MetaData()


# ============================================================================
# Row Types and Table Definitions
# ============================================================================

SerializedGrant = dict[str, typing.Any]


class AuthRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    name: typing.Annotated[str, orm.Col(index=True)]
    client_type: str
    description: str
    created_at: int
    is_enabled: bool
    type: str
    config: bytes


auth = orm.make_table(
    "auth",
    metadata,
    AuthRow,
    sqlalchemy.UniqueConstraint("name", "client_type"),
    sqlite_autoincrement=True,
)


class PublicKeyDenylistRow(typing.NamedTuple):
    id: typing.Annotated[str, orm.Col(index=True, unique=True, nullable=False)]
    key_id: str
    created_at: int


public_key_denylist = orm.make_table("public_key_denylist", metadata, PublicKeyDenylistRow)


class IdentityAccountKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, orm.Col(index=True, unique=True, nullable=False)]
    public_key: dict[str, typing.Any]
    identity_id: int
    created_at: int
    is_revoked: bool
    revoked_at: int | None


identity_account_key = orm.make_table("identity_account_key", metadata, IdentityAccountKeyRow)


class IdentitySessionKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, orm.Col(index=True, unique=True, nullable=False)]
    public_key: dict[str, typing.Any]
    identity_id: int
    created_at: int
    is_revoked: bool
    revoked_at: int | None
    expires_at: int
    login_ip: str | None
    role_id: int | None
    logged_out_at: int | None


identity_session_key = orm.make_table("identity_session_key", metadata, IdentitySessionKeyRow)


class IdentityInvitationKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, orm.Col(index=True, unique=True, nullable=False)]
    key: bytes
    identity_id: int
    created_at: int
    revoked_at: int | None
    accepted_at: int | None
    expires_at: int
    is_revoked: bool
    is_accepted: bool
    accepted_public_key_id: str | None


identity_invitation_key = orm.make_table("identity_invitation_key", metadata, IdentityInvitationKeyRow)


class TagRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    name: str
    value: str


tag = orm.make_table(
    "tag",
    metadata,
    TagRow,
    sqlalchemy.UniqueConstraint("name", "value", name="uix_name_value"),
    sqlite_autoincrement=True,
)


class IdentityRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    created_by_id: int | None
    created_at: int
    name: typing.Annotated[str, orm.Col(unique=True)]
    unix_username: typing.Annotated[str | None, orm.Col(unique=True)] = None


identity = orm.make_table("identity", metadata, IdentityRow, sqlite_autoincrement=True)


class IdentityBoundaryRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    identity_id: int
    boundary_id: int


identity_boundary = orm.make_table(
    "identity_boundary",
    metadata,
    IdentityBoundaryRow,
    sqlalchemy.UniqueConstraint("identity_id", "boundary_id", name="uix_identity_id_boundary_id"),
    sqlite_autoincrement=True,
)


class IdentityTagRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    identity_id: int
    tag_id: int


identity_tag = orm.make_table(
    "identity_tag",
    metadata,
    IdentityTagRow,
    sqlalchemy.UniqueConstraint("identity_id", "tag_id", name="uix_identity_id_tag_id"),
    sqlite_autoincrement=True,
)


class RoleRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    name: str
    description: str
    grant_list: list[SerializedGrant]


role = orm.make_table(
    "role",
    metadata,
    RoleRow,
    sqlalchemy.UniqueConstraint("name", name="uix_role_name"),
    sqlite_autoincrement=True,
)


class RoleMemberRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    role_id: int
    identity_id: int


role_member = orm.make_table(
    "role_member",
    metadata,
    RoleMemberRow,
    sqlalchemy.UniqueConstraint("role_id", "identity_id", name="uix_role_id_identity_id"),
    sqlite_autoincrement=True,
)


class BoundaryRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    name: str
    description: str
    ceiling_list: list[SerializedGrant] | None
    denied_list: list[SerializedGrant]


boundary = orm.make_table(
    "boundary",
    metadata,
    BoundaryRow,
    sqlalchemy.UniqueConstraint("name", name="uix_boundary_name"),
    sqlite_autoincrement=True,
)


class SigningKeyRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    type: int
    key: bytes
    serial_number: int
    valid_after: int
    valid_before: int


signing_key = orm.make_table(
    "signing_key",
    metadata,
    SigningKeyRow,
    sqlalchemy.Index("idx_valid_before_valid_after", "valid_before", "valid_after"),
    sqlite_autoincrement=True,
)


class BastionRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    url: str
    ssh_proxy_jump: str | None
    tag_id_list: list[int]
    created_at: int
    created_by_id: int | None


bastion = orm.make_table("bastion", metadata, BastionRow, sqlite_autoincrement=True)


class AuditLogRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    at: int
    level: int
    type: str
    by_identity_id: str | None
    details: dict[str, typing.Any]


audit_log = orm.make_table(
    "audit_log",
    metadata,
    AuditLogRow,
    sqlalchemy.Index("idx_audit_log_type", "type"),
    sqlalchemy.Index("idx_audit_log_by_identity_id", "by_identity_id"),
    sqlalchemy.Index("idx_audit_log_at", "at"),
    sqlite_autoincrement=True,
)


class OidcKeyRow(typing.NamedTuple):
    id: typing.Annotated[int, orm.Col(primary_key=True)]
    private_key: bytes
    public_key: dict[str, typing.Any]
    valid_after: int
    valid_before: int
    created_at: int


oidc_key = orm.make_table(
    "oidc_key",
    metadata,
    OidcKeyRow,
    sqlalchemy.Index("idx_oidc_key_valid", "valid_before", "valid_after"),
    sqlite_autoincrement=True,
)


class OidcNonceRow(typing.NamedTuple):
    nonce: typing.Annotated[str, orm.Col(primary_key=True)]
    expires_at: int


oidc_nonce = orm.make_table("oidc_nonce", metadata, OidcNonceRow)


class SshConnectionRow(typing.NamedTuple):
    connection_id: typing.Annotated[str, orm.Col(primary_key=True)]
    identity_id: int
    hostname: str
    deadline: int | None
    valid_before: int


ssh_connection = orm.make_table(
    "ssh_connection",
    metadata,
    SshConnectionRow,
    sqlalchemy.Index("idx_ssh_connection_valid_before", "valid_before"),
)


# ============================================================================
# Typed DAO
# ============================================================================


class AppDb(orm.Dao):
    """Typed DAO for the application database.

    Each property returns Table[XxxRow], so pyright sees concrete row types
    on read_one(), read_all(), etc.
    """

    @property
    def auth(self) -> orm.Table[AuthRow]:
        return self._get(auth)

    @property
    def public_key_denylist(self) -> orm.Table[PublicKeyDenylistRow]:
        return self._get(public_key_denylist)

    @property
    def identity_account_key(self) -> orm.Table[IdentityAccountKeyRow]:
        return self._get(identity_account_key)

    @property
    def identity_session_key(self) -> orm.Table[IdentitySessionKeyRow]:
        return self._get(identity_session_key)

    @property
    def identity_invitation_key(self) -> orm.Table[IdentityInvitationKeyRow]:
        return self._get(identity_invitation_key)

    @property
    def tag(self) -> orm.Table[TagRow]:
        return self._get(tag)

    @property
    def identity(self) -> orm.Table[IdentityRow]:
        return self._get(identity)

    @property
    def identity_boundary(self) -> orm.Table[IdentityBoundaryRow]:
        return self._get(identity_boundary)

    @property
    def identity_tag(self) -> orm.Table[IdentityTagRow]:
        return self._get(identity_tag)

    @property
    def role(self) -> orm.Table[RoleRow]:
        return self._get(role)

    @property
    def role_member(self) -> orm.Table[RoleMemberRow]:
        return self._get(role_member)

    @property
    def boundary(self) -> orm.Table[BoundaryRow]:
        return self._get(boundary)

    @property
    def signing_key(self) -> orm.Table[SigningKeyRow]:
        return self._get(signing_key)

    @property
    def bastion(self) -> orm.Table[BastionRow]:
        return self._get(bastion)

    @property
    def audit_log(self) -> orm.Table[AuditLogRow]:
        return self._get(audit_log)

    @property
    def oidc_key(self) -> orm.Table[OidcKeyRow]:
        return self._get(oidc_key)

    @property
    def oidc_nonce(self) -> orm.Table[OidcNonceRow]:
        return self._get(oidc_nonce)

    @property
    def ssh_connection(self) -> orm.Table[SshConnectionRow]:
        return self._get(ssh_connection)


def create(connection: sqlalchemy.engine.Connection) -> AppDb:
    """Create a typed DAO for the application database."""
    return AppDb(connection, metadata)
