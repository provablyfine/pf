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
        if "auth" not in self._tables:
            self._tables["auth"] = db.Table(self._connection, self._metadata.tables["auth"], AuthRow)
        return self._tables["auth"]  # type: ignore[return-value]

    @property
    def public_key_denylist(self) -> db.Table[PublicKeyDenylistRow]:
        if "public_key_denylist" not in self._tables:
            self._tables["public_key_denylist"] = db.Table(
                self._connection, self._metadata.tables["public_key_denylist"], PublicKeyDenylistRow
            )
        return self._tables["public_key_denylist"]  # type: ignore[return-value]

    @property
    def identity_account_key(self) -> db.Table[IdentityAccountKeyRow]:
        if "identity_account_key" not in self._tables:
            self._tables["identity_account_key"] = db.Table(
                self._connection, self._metadata.tables["identity_account_key"], IdentityAccountKeyRow
            )
        return self._tables["identity_account_key"]  # type: ignore[return-value]

    @property
    def identity_session_key(self) -> db.Table[IdentitySessionKeyRow]:
        if "identity_session_key" not in self._tables:
            self._tables["identity_session_key"] = db.Table(
                self._connection, self._metadata.tables["identity_session_key"], IdentitySessionKeyRow
            )
        return self._tables["identity_session_key"]  # type: ignore[return-value]

    @property
    def identity_invitation_key(self) -> db.Table[IdentityInvitationKeyRow]:
        if "identity_invitation_key" not in self._tables:
            self._tables["identity_invitation_key"] = db.Table(
                self._connection, self._metadata.tables["identity_invitation_key"], IdentityInvitationKeyRow
            )
        return self._tables["identity_invitation_key"]  # type: ignore[return-value]

    @property
    def tag(self) -> db.Table[TagRow]:
        if "tag" not in self._tables:
            self._tables["tag"] = db.Table(self._connection, self._metadata.tables["tag"], TagRow)
        return self._tables["tag"]  # type: ignore[return-value]

    @property
    def identity(self) -> db.Table[IdentityRow]:
        if "identity" not in self._tables:
            self._tables["identity"] = db.Table(
                self._connection, self._metadata.tables["identity"], IdentityRow
            )
        return self._tables["identity"]  # type: ignore[return-value]

    @property
    def identity_boundary(self) -> db.Table[IdentityBoundaryRow]:
        if "identity_boundary" not in self._tables:
            self._tables["identity_boundary"] = db.Table(
                self._connection, self._metadata.tables["identity_boundary"], IdentityBoundaryRow
            )
        return self._tables["identity_boundary"]  # type: ignore[return-value]

    @property
    def identity_tag(self) -> db.Table[IdentityTagRow]:
        if "identity_tag" not in self._tables:
            self._tables["identity_tag"] = db.Table(
                self._connection, self._metadata.tables["identity_tag"], IdentityTagRow
            )
        return self._tables["identity_tag"]  # type: ignore[return-value]

    @property
    def role(self) -> db.Table[RoleRow]:
        if "role" not in self._tables:
            self._tables["role"] = db.Table(self._connection, self._metadata.tables["role"], RoleRow)
        return self._tables["role"]  # type: ignore[return-value]

    @property
    def role_member(self) -> db.Table[RoleMemberRow]:
        if "role_member" not in self._tables:
            self._tables["role_member"] = db.Table(
                self._connection, self._metadata.tables["role_member"], RoleMemberRow
            )
        return self._tables["role_member"]  # type: ignore[return-value]

    @property
    def boundary(self) -> db.Table[BoundaryRow]:
        if "boundary" not in self._tables:
            self._tables["boundary"] = db.Table(
                self._connection, self._metadata.tables["boundary"], BoundaryRow
            )
        return self._tables["boundary"]  # type: ignore[return-value]

    @property
    def signing_key(self) -> db.Table[SigningKeyRow]:
        if "signing_key" not in self._tables:
            self._tables["signing_key"] = db.Table(
                self._connection, self._metadata.tables["signing_key"], SigningKeyRow
            )
        return self._tables["signing_key"]  # type: ignore[return-value]

    @property
    def default(self) -> db.Table[DefaultRow]:
        if "default" not in self._tables:
            self._tables["default"] = db.Table(self._connection, self._metadata.tables["default"], DefaultRow)
        return self._tables["default"]  # type: ignore[return-value]

    @property
    def bastion(self) -> db.Table[BastionRow]:
        if "bastion" not in self._tables:
            self._tables["bastion"] = db.Table(self._connection, self._metadata.tables["bastion"], BastionRow)
        return self._tables["bastion"]  # type: ignore[return-value]

    @property
    def audit_log(self) -> db.Table[AuditLogRow]:
        if "audit_log" not in self._tables:
            self._tables["audit_log"] = db.Table(
                self._connection, self._metadata.tables["audit_log"], AuditLogRow
            )
        return self._tables["audit_log"]  # type: ignore[return-value]

    @property
    def oauth2_login_request(self) -> db.Table[OAuth2LoginRequestRow]:
        if "oauth2_login_request" not in self._tables:
            self._tables["oauth2_login_request"] = db.Table(
                self._connection, self._metadata.tables["oauth2_login_request"], OAuth2LoginRequestRow
            )
        return self._tables["oauth2_login_request"]  # type: ignore[return-value]

    @property
    def oidc_key(self) -> db.Table[OidcKeyRow]:
        if "oidc_key" not in self._tables:
            self._tables["oidc_key"] = db.Table(
                self._connection, self._metadata.tables["oidc_key"], OidcKeyRow
            )
        return self._tables["oidc_key"]  # type: ignore[return-value]


def create(connection: sqlalchemy.engine.Connection) -> AppDb:
    """Create a typed DAO for the application database."""
    return AppDb(connection, metadata)


def create_tables(url: str) -> None:
    """Create all tables in the database."""
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
