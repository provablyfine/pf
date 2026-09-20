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

# The root tenant is addressed by a well-known UUID so that deployment tooling can find it.
# Every other tenant gets a random UUID. Knowing a UUID is what lets a client reach a tenant,
# so tenant names are never used in URLs.
ROOT_TENANT_UUID = "00000000-0000-0000-0000-000000000001"


# ============================================================================
# Row Type and Table Definition
# ============================================================================


class TenantRow(typing.NamedTuple):
    id: typing.Annotated[int, db.Col(primary_key=True, nullable=False)]
    uuid: typing.Annotated[str, db.Col(nullable=False, unique=True)]
    name: str
    display_name: str
    owner_id: int | None
    database_url: str
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int


tenant = db.make_table("tenant", metadata, TenantRow, sqlite_autoincrement=True)


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
        return self._get(tenant)


def create(connection: sqlalchemy.engine.Connection) -> RegistryDb:
    """Create a typed DAO for the registry database."""
    return RegistryDb(connection, metadata)
