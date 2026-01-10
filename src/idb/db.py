import enum

import sqlalchemy

@enum.unique
class AuditLogLevel(enum.IntEnum):
    INFO = 1
    WARNING = 2


# Database table definitions.
metadata = sqlalchemy.MetaData()


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

tags = sqlalchemy.Table(
    "tags",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("value", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.UniqueConstraint('name', 'value', name='uix_name_value'),
)

identity = sqlalchemy.Table(
    "identity",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("created_by", sqlalchemy.Integer, index=False, unique=False, nullable=True),
    sqlalchemy.Column("boundaries", sqlalchemy.JSON, index=False, unique=False, nullable=False),
    sqlalchemy.Column("name", sqlalchemy.String, index=False, unique=True, nullable=False),
    sqlalchemy.Column("detail", sqlalchemy.JSON, index=False, unique=False, nullable=False),
    sqlalchemy.Column("tag_id", sqlalchemy.JSON, index=False, unique=False, nullable=False),
)

role = sqlalchemy.Table(
    "role",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=False, unique=True, nullable=False),
    sqlalchemy.Column("description", sqlalchemy.String, index=False, unique=False, nullable=False),
    sqlalchemy.Column("permissions", sqlalchemy.JSON, index=False, unique=False, nullable=False),
)

role_grant = sqlalchemy.Table(
    "role_grant",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("role_id", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.String, index=True, unique=False, nullable=False),
)

boundary = sqlalchemy.Table(
    "boundary",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=False, unique=True, nullable=False),
    sqlalchemy.Column("description", sqlalchemy.String, index=False, unique=False, nullable=False),
    sqlalchemy.Column("denies", sqlalchemy.JSON, nullable=False),
)

default = sqlalchemy.Table(
    "default",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("boundary_id", sqlalchemy.Integer, index=True, unique=False, nullable=False),
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
