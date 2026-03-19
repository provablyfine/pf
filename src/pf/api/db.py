import enum

import sqlalchemy


@enum.unique
class AuditLogLevel(enum.IntEnum):
    INFO = 1
    WARNING = 2


@enum.unique
class SigningKeyType(enum.IntEnum):
    HOST = 1
    USER = 2


# Database table definitions.
metadata = sqlalchemy.MetaData()


auth = sqlalchemy.Table(
    "auth",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, nullable=False, unique=True, index=True),
    sqlalchemy.Column("tag_id_list", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("is_enabled", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("type", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("config", sqlalchemy.JSON, nullable=False),
)

public_key_denylist = sqlalchemy.Table(
    "public_key_denylist",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("key_id", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.Integer, nullable=False),
)

identity_account_key = sqlalchemy.Table(
    "identity_account_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("public_key", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=False, unique=False, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=True),
)

identity_session_key = sqlalchemy.Table(
    "identity_session_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("public_key", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=False, unique=False, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=True),
    sqlalchemy.Column("expires_at", sqlalchemy.INTEGER, nullable=False),
)

identity_invitation_key = sqlalchemy.Table(
    "identity_invitation_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("key", sqlalchemy.LargeBinary, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=False, unique=False, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=True),
    sqlalchemy.Column("accepted_at", sqlalchemy.INTEGER, nullable=True),
    sqlalchemy.Column("expires_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("is_accepted", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("accepted_public_key_id", sqlalchemy.String, nullable=True),
)

tag = sqlalchemy.Table(
    "tag",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("value", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.UniqueConstraint("name", "value", name="uix_name_value"),
    # We need autoincrement to make sure ids are not recycled EVER.
    sqlite_autoincrement=True,
)

identity = sqlalchemy.Table(
    "identity",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("created_by_id", sqlalchemy.Integer, index=False, unique=False, nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("name", sqlalchemy.String, index=True, unique=True, nullable=False),
    # We need autoincrement to make sure ids are not recycled EVER.
    sqlite_autoincrement=True,
)

identity_boundary = sqlalchemy.Table(
    "identity_boundary",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.Column("boundary_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.UniqueConstraint("identity_id", "boundary_id", name="uix_identity_id_boundary_id"),
)

identity_tag = sqlalchemy.Table(
    "identity_tag",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.Column("tag_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.UniqueConstraint("identity_id", "tag_id", name="uix_identity_id_tag_id"),
)

role = sqlalchemy.Table(
    "role",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("description", sqlalchemy.String, index=False, unique=False, nullable=False),
    sqlalchemy.Column("grant_list", sqlalchemy.JSON, index=False, unique=False, nullable=False),
    # We need autoincrement to make sure ids are not recycled EVER.
    sqlite_autoincrement=True,
)

role_member = sqlalchemy.Table(
    "role_member",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("role_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
)

boundary = sqlalchemy.Table(
    "boundary",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=False, unique=True, nullable=False),
    sqlalchemy.Column("description", sqlalchemy.String, index=False, unique=False, nullable=False),
    sqlalchemy.Column("ceiling_list", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("denied_list", sqlalchemy.JSON, nullable=False),
    # We need autoincrement to make sure ids are not recycled EVER.
    sqlite_autoincrement=True,
)

signing_key = sqlalchemy.Table(
    "signing_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("type", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("key", sqlalchemy.LargeBinary, nullable=False),
    sqlalchemy.Column("serial_number", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("valid_after", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("valid_before", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Index("idx_valid_before_valid_after", "valid_before", "valid_after"),
    # We need autoincrement to make sure ids are not recycled EVER.
    sqlite_autoincrement=True,
)

default = sqlalchemy.Table(
    "default",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
)

audit_log = sqlalchemy.Table(
    "audit_log",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("at", sqlalchemy.Integer, nullable=False),
    sqlalchemy.Column("level", sqlalchemy.Integer, index=True, unique=False, nullable=False),
    sqlalchemy.Column("type", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("by_identity_id", sqlalchemy.String, index=True, unique=False, nullable=True),
    sqlalchemy.Column("details", sqlalchemy.JSON, nullable=False),
)


def create_tables(url):
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
