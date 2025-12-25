import sqlalchemy

# Database table definitions.
metadata = sqlalchemy.MetaData()


identity_key = sqlalchemy.Table(
    "identity_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("identity_key", sqlalchemy.JSON, nullable=False),
    #    sqlalchemy.Column("public_key", sqlalchemy.JSON, nullable=False),
    #    sqlalchemy.Column("identity_id", sqlalchemy.String, index=False, unique=False, nullable=False),
    #    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    #    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    #    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=False),
)

session_key = sqlalchemy.Table(
    "session_key",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("public_key", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.String, index=False, unique=False, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=False),
    sqlalchemy.Column("expires_at", sqlalchemy.INTEGER, nullable=False),
)

identity_invitation = sqlalchemy.Table(
    "identity_invitation",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("identity_invitation", sqlalchemy.JSON, nullable=False),
    #    sqlalchemy.Column("key", sqlalchemy.String, nullable=False),
    #    sqlalchemy.Column("identity_id", sqlalchemy.String, index=False, unique=False, nullable=False),
    #    sqlalchemy.Column("created_at", sqlalchemy.INTEGER, nullable=False),
    #    sqlalchemy.Column("is_revoked", sqlalchemy.Boolean, nullable=False),
    #    sqlalchemy.Column("revoked_at", sqlalchemy.INTEGER, nullable=False),
    #    sqlalchemy.Column("expires_at", sqlalchemy.INTEGER, nullable=False),
)

identity = sqlalchemy.Table(
    "identity",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("identity", sqlalchemy.JSON, nullable=False),
)

role = sqlalchemy.Table(
    "role",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("role", sqlalchemy.JSON, nullable=False),
)

role_identity_grant = sqlalchemy.Table(
    "role_identity_grant",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("role_id", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.String, index=True, unique=False, nullable=False),
)

role_group_grant = sqlalchemy.Table(
    "role_group_grant",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("role_id", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("group_id", sqlalchemy.String, index=True, unique=False, nullable=False),
)

group = sqlalchemy.Table(
    "group",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("group", sqlalchemy.JSON, nullable=False),
)

group_membership = sqlalchemy.Table(
    "group_membership",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("group_id", sqlalchemy.String, index=True, unique=False, nullable=False),
    sqlalchemy.Column("identity_id", sqlalchemy.String, index=True, unique=False, nullable=False),
)

boundary = sqlalchemy.Table(
    "boundary",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, index=True, unique=True, nullable=False),
    sqlalchemy.Column("boundary", sqlalchemy.JSON, nullable=False),
)

default = sqlalchemy.Table(
    "default",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("boundary_id", sqlalchemy.String, index=True, unique=False, nullable=False),
)

audit_log = sqlalchemy.Table(
    "audit_log",
    metadata,
    sqlalchemy.Column("log", sqlalchemy.JSON, nullable=False),
)

def create_tables(url):
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
