"""Application database schema and typed DAO.

Tables are defined as NamedTuple classes (single source of truth for column types)
and generated via make_table(). The AppDb typed DAO exposes each table with its
row type visible to pyright.
"""

import enum
import typing

import sqlalchemy

from . import db

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


class AuthRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    name: typing.Annotated[str, db.Col(unique=True, index=True)]
    description: typing.Annotated[str, db.Col(server_default="")]
    tag_id_list: dict[str, typing.Any]
    created_at: int
    is_enabled: bool
    type: str
    config: bytes


auth = db.make_table("auth", metadata, AuthRow)


class PublicKeyDenylistRow(typing.NamedTuple):
    id: typing.Annotated[str, db.Col(index=True, unique=True, nullable=False)]
    key_id: str
    created_at: int


public_key_denylist = db.make_table("public_key_denylist", metadata, PublicKeyDenylistRow)


class IdentityAccountKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, db.Col(index=True, unique=True, nullable=False)]
    public_key: dict[str, typing.Any]
    identity_id: int
    created_at: int
    is_revoked: bool
    revoked_at: int | None


identity_account_key = db.make_table("identity_account_key", metadata, IdentityAccountKeyRow)


class IdentitySessionKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, db.Col(index=True, unique=True, nullable=False)]
    public_key: dict[str, typing.Any]
    identity_id: int
    created_at: int
    is_revoked: bool
    revoked_at: int | None
    expires_at: int
    login_ip: str | None


identity_session_key = db.make_table("identity_session_key", metadata, IdentitySessionKeyRow)


class IdentityInvitationKeyRow(typing.NamedTuple):
    id: typing.Annotated[str, db.Col(index=True, unique=True, nullable=False)]
    key: bytes
    identity_id: int
    created_at: int
    revoked_at: int | None
    accepted_at: int | None
    expires_at: int
    is_revoked: bool
    is_accepted: bool
    accepted_public_key_id: str | None


identity_invitation_key = db.make_table("identity_invitation_key", metadata, IdentityInvitationKeyRow)


class TagRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    name: str
    value: str


tag = db.make_table(
    "tag",
    metadata,
    TagRow,
    sqlalchemy.UniqueConstraint("name", "value", name="uix_name_value"),
    sqlite_autoincrement=True,
)


class IdentityRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    created_by_id: int | None
    created_at: int
    name: str


identity = db.make_table("identity", metadata, IdentityRow, sqlite_autoincrement=True)


class IdentityBoundaryRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    identity_id: int
    boundary_id: int


identity_boundary = db.make_table(
    "identity_boundary",
    metadata,
    IdentityBoundaryRow,
    sqlalchemy.UniqueConstraint("identity_id", "boundary_id", name="uix_identity_id_boundary_id"),
)


class IdentityTagRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    identity_id: int
    tag_id: int


identity_tag = db.make_table(
    "identity_tag",
    metadata,
    IdentityTagRow,
    sqlalchemy.UniqueConstraint("identity_id", "tag_id", name="uix_identity_id_tag_id"),
)


class RoleRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    name: str
    description: str
    grant_list: dict[str, typing.Any]


role = db.make_table("role", metadata, RoleRow, sqlite_autoincrement=True)


class RoleMemberRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    role_id: int
    identity_id: int


role_member = db.make_table("role_member", metadata, RoleMemberRow)


class BoundaryRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    name: str
    description: str
    ceiling_list: dict[str, typing.Any]
    denied_list: dict[str, typing.Any]


boundary = db.make_table("boundary", metadata, BoundaryRow, sqlite_autoincrement=True)


class SigningKeyRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    type: int
    key: bytes
    serial_number: int
    valid_after: int
    valid_before: int


signing_key = db.make_table(
    "signing_key",
    metadata,
    SigningKeyRow,
    sqlalchemy.Index("idx_valid_before_valid_after", "valid_before", "valid_after"),
    sqlite_autoincrement=True,
)


class DefaultRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]


default = db.make_table("default", metadata, DefaultRow)


class BastionRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    register_url: str
    connect_url: str | None
    ssh_proxy_jump: str | None
    tag_id_list: typing.Annotated[list[int], db.Col(server_default="[]")]
    created_at: int
    created_by_id: int | None


bastion = db.make_table("bastion", metadata, BastionRow, sqlite_autoincrement=True)


class AuditLogRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    at: int
    level: int
    type: str
    by_identity_id: str | None
    details: dict[str, typing.Any]


audit_log = db.make_table("audit_log", metadata, AuditLogRow)


class OAuth2LoginRequestRow(typing.NamedTuple):
    id: typing.Annotated[str, db.Col(primary_key=True)]
    session_key_thumbprint: str
    session_public_key: dict[str, typing.Any]
    auth_config_id: int
    code_verifier: bytes
    redirect_uri: str
    client_redirect_uri: str
    created_at: int
    expires_at: int


oauth2_login_request = db.make_table("oauth2_login_request", metadata, OAuth2LoginRequestRow)


class OidcKeyRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True)]
    private_key: bytes
    public_key: dict[str, typing.Any]
    valid_after: int
    valid_before: int
    created_at: int


oidc_key = db.make_table(
    "oidc_key",
    metadata,
    OidcKeyRow,
    sqlalchemy.Index("idx_oidc_key_valid", "valid_before", "valid_after"),
    sqlite_autoincrement=True,
)


# ============================================================================
# Typed DAO
# ============================================================================


class AppDb(db.Dao):
    """Typed DAO for the application database.

    Each property returns Table[XxxRow], so pyright sees concrete row types
    on read_one(), read_all(), etc.
    """

    @property
    def auth(self) -> db.Table[AuthRow]:
        return self._get(auth)

    @property
    def public_key_denylist(self) -> db.Table[PublicKeyDenylistRow]:
        return self._get(public_key_denylist)

    @property
    def identity_account_key(self) -> db.Table[IdentityAccountKeyRow]:
        return self._get(identity_account_key)

    @property
    def identity_session_key(self) -> db.Table[IdentitySessionKeyRow]:
        return self._get(identity_session_key)

    @property
    def identity_invitation_key(self) -> db.Table[IdentityInvitationKeyRow]:
        return self._get(identity_invitation_key)

    @property
    def tag(self) -> db.Table[TagRow]:
        return self._get(tag)

    @property
    def identity(self) -> db.Table[IdentityRow]:
        return self._get(identity)

    @property
    def identity_boundary(self) -> db.Table[IdentityBoundaryRow]:
        return self._get(identity_boundary)

    @property
    def identity_tag(self) -> db.Table[IdentityTagRow]:
        return self._get(identity_tag)

    @property
    def role(self) -> db.Table[RoleRow]:
        return self._get(role)

    @property
    def role_member(self) -> db.Table[RoleMemberRow]:
        return self._get(role_member)

    @property
    def boundary(self) -> db.Table[BoundaryRow]:
        return self._get(boundary)

    @property
    def signing_key(self) -> db.Table[SigningKeyRow]:
        return self._get(signing_key)

    @property
    def default(self) -> db.Table[DefaultRow]:
        return self._get(default)

    @property
    def bastion(self) -> db.Table[BastionRow]:
        return self._get(bastion)

    @property
    def audit_log(self) -> db.Table[AuditLogRow]:
        return self._get(audit_log)

    @property
    def oauth2_login_request(self) -> db.Table[OAuth2LoginRequestRow]:
        return self._get(oauth2_login_request)

    @property
    def oidc_key(self) -> db.Table[OidcKeyRow]:
        return self._get(oidc_key)


def create(connection: sqlalchemy.engine.Connection) -> AppDb:
    """Create a typed DAO for the application database."""
    return AppDb(connection, metadata)


def create_tables(url: str) -> None:
    """Create all tables in the database."""
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
