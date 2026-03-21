import sqlalchemy

tenant_metadata = sqlalchemy.MetaData()

tenant = sqlalchemy.Table(
    "tenant",
    tenant_metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("name", sqlalchemy.String, nullable=False, unique=True),
    sqlalchemy.Column("display_name", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("owner_id", sqlalchemy.Integer, nullable=True),
    sqlalchemy.Column("database_url", sqlalchemy.String, nullable=False),
    sqlalchemy.Column("is_enabled", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("is_initialized", sqlalchemy.Boolean, nullable=False),
    sqlalchemy.Column("is_deleted", sqlalchemy.Boolean, nullable=False, server_default=sqlalchemy.false()),
    sqlalchemy.Column("created_at", sqlalchemy.Integer, nullable=False),
)


def create_tables(url: str) -> None:
    engine = sqlalchemy.create_engine(url)
    tenant_metadata.create_all(engine)
