"""Registry database schema and typed DAO.

The registry database tracks all tenants. Tables are defined as NamedTuple classes
(single source of truth for column types) and generated via make_table().
The RegistryDb typed DAO exposes each table with its row type visible to pyright.
"""

import typing

import sqlalchemy

from . import db

# Database metadata
metadata = sqlalchemy.MetaData()


# ============================================================================
# Row Type and Table Definition
# ============================================================================


class TenantRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True, nullable=False)]
    name: typing.Annotated[str, db.Col(nullable=False, unique=True)]
    display_name: typing.Annotated[str, db.Col(nullable=False)]
    owner_id: int | None
    database_url: str
    is_enabled: bool
    is_initialized: bool
    is_deleted: typing.Annotated[bool, db.Col(server_default=sqlalchemy.false())]
    created_at: int


tenant = db.make_table("tenant", metadata, TenantRow)


# ============================================================================
# Typed DAO
# ============================================================================


class RegistryDb(db.Dao):
    """Typed DAO for the tenant registry database.

    Each property returns Table[XxxRow], so pyright sees concrete row types
    on read_one(), read_all(), etc.
    """

    @property
    def tenant(self) -> db.Table[TenantRow]:
        if "tenant" not in self._tables:
            self._tables["tenant"] = db.Table(self._connection, self._metadata.tables["tenant"], TenantRow)
        return self._tables["tenant"]  # type: ignore[return-value]


def create(connection: sqlalchemy.engine.Connection) -> RegistryDb:
    """Create a typed DAO for the registry database."""
    return RegistryDb(connection, metadata)


def create_tables(url: str) -> None:
    """Create all tables in the registry database."""
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
