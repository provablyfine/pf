import sqlalchemy

# Database table definitions.
metadata = sqlalchemy.MetaData()

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
