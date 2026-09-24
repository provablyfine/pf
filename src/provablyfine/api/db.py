from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import dataclasses
import logging
import os
import re
import sqlite3
import types
import typing

import sqlalchemy
import sqlalchemy.event
import sqlalchemy.exc

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Col:
    """Column metadata for use in Annotated type hints.

    Carries SQLAlchemy-specific options that can't be inferred from Python types.
    Used in NamedTuple field annotations to specify primary_key, unique, index, etc.

    Example:
        class IdentityRow(typing.NamedTuple):
            id: typing.Annotated[int, Col(primary_key=True)]
            name: str
    """

    sa_type: sqlalchemy.types.TypeEngine[typing.Any] | None = None
    primary_key: bool = False
    nullable: bool = False
    unique: bool = False
    index: bool = False


@dataclasses.dataclass
class TableDef[T]:
    """Metadata for a table definition: the SQLAlchemy table + its NamedTuple row type.

    Returned by make_table() so that typed DAOs can record the name→row_type mapping
    and use _get() to reduce boilerplate.
    """

    table: sqlalchemy.Table
    row_type: type[T]


class Table[T]:
    def __init__(
        self,
        connection: sqlalchemy.engine.Connection,
        table: sqlalchemy.Table,
        row_type: type[T],
    ) -> None:
        self._connection = connection
        self._table = table
        self._row_type = row_type
        self.columns = types.SimpleNamespace(**dict(table.columns))  # type: ignore[misc]

    @property
    def column(self) -> types.SimpleNamespace:
        return self.columns

    def create(self, **kwargs: typing.Any) -> int | None:
        statement = self._table.insert().values(**kwargs)
        result = self._connection.execute(statement)
        primary_key: typing.Any = result.inserted_primary_key
        if primary_key is None or len(primary_key) == 0:
            return None
        if len(primary_key) == 1:
            return primary_key[0]
        raise AssertionError("Multiple primary keys not supported")

    def _where(self, statement: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        for arg in args:
            statement = statement.where(arg)
        for k, v in kwargs.items():
            column = self._table.columns[k]
            if isinstance(v, list | tuple | set):
                statement = statement.where(column.in_(v))  # type: ignore[arg-type]
            else:
                statement = statement.where(column == v)
        return statement

    def read_one(self, *args: typing.Any, **kwargs: typing.Any) -> T | None:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        for row in rows:
            return self._row_type(*row)
        return None

    def read_all(self, *args: typing.Any, **kwargs: typing.Any) -> list[T]:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        return [self._row_type(*row) for row in rows]

    def update(self, **kwargs: typing.Any) -> Update:
        statement = self._table.update().values(**kwargs)
        return Update(self, statement)

    def delete(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        statement = self._table.delete()
        statement = self._where(statement, *args, **kwargs)
        self._connection.execute(statement)


class Update:
    def __init__(self, outer: Table[typing.Any], statement: typing.Any) -> None:
        self._outer: Table[typing.Any] = outer
        self._statement = statement

    def where(self, **kwargs: typing.Any) -> int:
        """Apply the update and return the number of rows it changed."""
        statement = self._outer._where(self._statement, **kwargs)  # type: ignore[protected-access]
        result = self._outer._connection.execute(statement)  # type: ignore[protected-access]
        return result.rowcount


class Dao:
    def __init__(self, connection: sqlalchemy.engine.Connection, metadata: sqlalchemy.MetaData) -> None:
        self._connection = connection
        self._metadata = metadata
        self._tables: dict[str, Table[typing.Any]] = {}

    def _get[T](self, table_def: TableDef[T]) -> Table[T]:
        """Get or create a typed Table instance from a TableDef.

        Used by typed DAO subclasses (AppDb, RegistryDb) to lazily instantiate
        and cache Table[T] instances.
        """
        name = table_def.table.name
        if name not in self._tables:
            self._tables[name] = Table(self._connection, table_def.table, table_def.row_type)
        return self._tables[name]  # type: ignore[return-value]


def create_engine(url: str, echo: bool = False) -> sqlalchemy.Engine:
    """Create an engine whose transactions are real transactions.

    With the sqlite3 driver's default mode, a transaction only starts at the first INSERT,
    UPDATE or DELETE. SELECT and DDL statements run outside of any transaction.
    Here the driver never starts transactions and SQLAlchemy sends BEGIN itself.
    Everything up to the commit is one transaction.

    Use `begin()` to start a transaction.
    """
    engine = sqlalchemy.create_engine(url, echo=echo)
    if engine.dialect.name == "sqlite":
        _begin_sqlite_transactions(engine)
    return engine


_WRITE_OPTION = "pf_write"


def _begin_sqlite_transactions(engine: sqlalchemy.Engine) -> None:
    """SQLite locks the whole file. A transaction that reads and then writes cannot always upgrade its lock.

    When two of them try at once, SQLite fails one immediately with "database is locked".
    A transaction that is going to write takes the write lock first with BEGIN IMMEDIATE.
    Other writers then wait their turn.
    """

    @sqlalchemy.event.listens_for(engine, "connect")
    def _disable_driver_transactions(dbapi_connection: sqlite3.Connection, _record: object) -> None:
        dbapi_connection.isolation_level = None

    @sqlalchemy.event.listens_for(engine, "begin")
    def _begin(conn: sqlalchemy.Connection) -> None:
        write = conn.get_execution_options().get(_WRITE_OPTION, False)
        conn.exec_driver_sql("BEGIN IMMEDIATE" if write else "BEGIN")


_DATABASE_NAME_RE = re.compile(r"^[a-z0-9_]+$")
_DATABASE_NAME_MAX_LENGTH = {"postgresql": 63, "mysql": 64, "mariadb": 64}


def _validate_database_name(name: str, dialect: str) -> None:
    if not _DATABASE_NAME_RE.match(name):
        raise ValueError(f"Invalid database name {name!r}: must match {_DATABASE_NAME_RE.pattern!r}")
    max_length = _DATABASE_NAME_MAX_LENGTH.get(dialect)
    if max_length is not None and len(name) > max_length:
        raise ValueError(f"Database name {name!r} has {len(name)} characters, over the {dialect} limit of {max_length}")


def _admin_database_name(dialect: str) -> str | None:
    """The database to connect to in order to run CREATE/DROP DATABASE.

    Postgres always needs an existing database to connect to; every server has one
    named "postgres". MySQL and MariaDB accept a connection with no database selected.
    """
    return "postgres" if dialect == "postgresql" else None


def _with_database(url: sqlalchemy.engine.URL, database: str | None) -> sqlalchemy.engine.URL:
    """Like `url.set(database=...)`, except database=None actually clears it.

    URL.set() treats a None argument as "leave this field alone", not "clear it",
    since None is also its default for "not provided". Passing database=None through
    it silently keeps the original database name instead of dropping it.
    """
    return sqlalchemy.engine.URL.create(
        drivername=url.drivername,
        username=url.username,
        password=url.password,
        host=url.host,
        port=url.port,
        database=database,
        query=url.query,
    )


def create_database(url: str, *, exist_ok: bool = False) -> None:
    """Create the database named in `url`, on its server.

    SQLite has no separate create-a-database step, but the directory that its file
    lives in (a tenants directory, or the registry file's own directory) may not exist
    yet. Postgres and MySQL/MariaDB need CREATE DATABASE issued against the server first.
    """
    made_url = sqlalchemy.make_url(url)
    dialect = made_url.get_backend_name()
    if dialect == "sqlite":
        db_path = made_url.database
        assert db_path is not None
        dirname = os.path.dirname(db_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        return
    db_name = made_url.database
    assert db_name is not None
    _validate_database_name(db_name, dialect)
    admin_url = _with_database(made_url, _admin_database_name(dialect))
    engine = sqlalchemy.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            quoted = conn.dialect.identifier_preparer.quote(db_name)
            statement = (
                f"CREATE DATABASE {quoted}"
                if dialect == "postgresql"
                else f"CREATE DATABASE {quoted} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
            )
            try:
                conn.exec_driver_sql(statement)
            except sqlalchemy.exc.DatabaseError:
                if not exist_ok:
                    raise
    finally:
        engine.dispose()


def drop_database(url: str, *, if_exists: bool = True) -> None:
    """Drop the database named in `url`, from its server. No-op for sqlite; see create_database.

    Callers must dispose every engine connected to this database before calling this:
    MySQL/MariaDB has no way to force-disconnect lingering connections, so a live
    connection can make this hang or fail. Postgres uses WITH (FORCE) to disconnect
    stragglers, but relying on that instead of disposing engines is not a substitute.
    """
    made_url = sqlalchemy.make_url(url)
    dialect = made_url.get_backend_name()
    if dialect == "sqlite":
        return
    db_name = made_url.database
    assert db_name is not None
    admin_url = _with_database(made_url, _admin_database_name(dialect))
    engine = sqlalchemy.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            quoted = conn.dialect.identifier_preparer.quote(db_name)
            exists_clause = "IF EXISTS " if if_exists else ""
            force = " WITH (FORCE)" if dialect == "postgresql" else ""
            conn.exec_driver_sql(f"DROP DATABASE {exists_clause}{quoted}{force}")
    finally:
        engine.dispose()


def _sqlite_tenants_dir(registry_url: str) -> str:
    """Where per-tenant sqlite files live: a "tenants" directory next to the registry file."""
    registry_path = sqlalchemy.make_url(registry_url).database
    assert registry_path is not None
    return os.path.join(os.path.dirname(registry_path), "tenants")


def derive_tenant_url(registry_url: str, tenant_uuid: str) -> str:
    """Derive a tenant's database URL from the registry's URL and the tenant's UUID.

    On a shared server (Postgres/MySQL), a tenant is a separate database on that same
    server, named after the registry database so that two registries sharing one
    physical server (e.g. two test runs against the same container) never collide on
    the same tenant database name. For sqlite, a tenant is one file, named after the
    tenant, in a "tenants" directory next to the registry's own file.
    """
    made_url = sqlalchemy.make_url(registry_url)
    dialect = made_url.get_backend_name()
    suffix = tenant_uuid.replace("-", "")
    if dialect == "sqlite":
        tenant_path = os.path.join(_sqlite_tenants_dir(registry_url), f"{suffix}.db")
        return f"sqlite:///{tenant_path}"
    registry_name = made_url.database
    assert registry_name is not None
    tenant_db_name = f"{registry_name}_t_{suffix}"
    _validate_database_name(tenant_db_name, dialect)
    return made_url.set(database=tenant_db_name).render_as_string(hide_password=False)


def begin(engine: sqlalchemy.Engine, write: bool = False) -> contextlib.AbstractContextManager[sqlalchemy.Connection]:
    """Start a transaction. It commits on success and rolls back on error.

    Pass write=True when the transaction is going to write. Correctness must never depend on it.
    It only makes concurrent writers wait instead of failing on databases that lock the whole file.
    """
    return engine.execution_options(**{_WRITE_OPTION: write}).begin()


@contextlib.asynccontextmanager
async def abegin(
    engine: sqlalchemy.Engine, write: bool = False
) -> collections.abc.AsyncGenerator[sqlalchemy.Connection]:
    """Like `begin()`, for code that runs on the event loop.

    Waiting for a lock, and committing, can take a while. Both happen in a worker thread,
    so that the event loop keeps running while the request waits.
    """
    transaction = begin(engine, write)
    conn = await asyncio.to_thread(transaction.__enter__)
    try:
        yield conn
    except BaseException as e:
        await asyncio.shield(asyncio.to_thread(transaction.__exit__, type(e), e, e.__traceback__))
        raise
    await asyncio.shield(asyncio.to_thread(transaction.__exit__, None, None, None))


def create(connection: sqlalchemy.engine.Connection, metadata: sqlalchemy.MetaData) -> Dao:
    return Dao(connection, metadata)


def _infer_sa_type(python_type: type) -> sqlalchemy.types.TypeEngine[typing.Any]:
    """Infer SQLAlchemy type from a Python type annotation."""
    # Strip Optional/Union wrappers
    origin = typing.get_origin(python_type)
    if origin in (typing.Union, types.UnionType):
        args = typing.get_args(python_type)
        if type(None) in args:
            # Optional[X] — recurse on the non-None type
            non_none = next(arg for arg in args if arg is not type(None))
            return _infer_sa_type(non_none)

    if python_type is int:
        return sqlalchemy.BigInteger().with_variant(sqlalchemy.Integer(), "sqlite")
    elif python_type is str:
        return sqlalchemy.String().with_variant(sqlalchemy.String(255), "mysql", "mariadb")
    elif python_type is bool:
        return sqlalchemy.Boolean()
    elif python_type is bytes:
        return sqlalchemy.LargeBinary()
    elif origin in (dict, list):
        return sqlalchemy.JSON()
    else:
        raise ValueError(f"Cannot infer SQLAlchemy type from {python_type}")


def _is_optional(hint: type) -> bool:
    """Check if a type hint is Optional[T] (Union[T, None])."""
    origin = typing.get_origin(hint)
    if origin in [typing.Union, types.UnionType]:
        args = typing.get_args(hint)
        return type(None) in args
    return False


def make_table[T](
    name: str,
    metadata: sqlalchemy.MetaData,
    row_cls: type[T],
    *constraints_and_indexes: typing.Any,
    **table_kwargs: typing.Any,
) -> TableDef[T]:
    """Generate a SQLAlchemy Table from a typed NamedTuple class.

    The NamedTuple is the single source of truth for column names and Python types.
    Column order in the generated Table matches field order in the NamedTuple.

    Args:
        name: Table name
        metadata: SQLAlchemy MetaData instance
        row_cls: A NamedTuple class. Fields are columns; Annotated values with Col()
                 provide SQLAlchemy-specific options.
        *constraints_and_indexes: Additional Table constraints/indexes (UniqueConstraint, Index)
        **table_kwargs: Additional table-level options (e.g. sqlite_autoincrement=True)

    Returns:
        A TableDef[T] instance containing the SQLAlchemy Table and row type
    """
    hints = typing.get_type_hints(row_cls, include_extras=True)
    columns: list[sqlalchemy.Column[typing.Any]] = []

    for field_name, hint in hints.items():
        col_spec = Col()
        python_type = hint

        # Extract Col metadata from Annotated
        if typing.get_origin(hint) is typing.Annotated:
            python_type, *extras = typing.get_args(hint)
            for extra in extras:
                if isinstance(extra, Col):
                    col_spec = extra
                    break

        sa_type = col_spec.sa_type or _infer_sa_type(python_type)
        nullable = col_spec.nullable or _is_optional(python_type)

        # Construct Column with explicit parameters to satisfy type stubs
        col = sqlalchemy.Column[typing.Any](
            field_name,
            sa_type,
            primary_key=col_spec.primary_key,
            nullable=nullable,
            unique=col_spec.unique or False,
            index=col_spec.index or False,
        )
        columns.append(col)

    sa_table = sqlalchemy.Table(name, metadata, *columns, *constraints_and_indexes, **table_kwargs)
    return TableDef(table=sa_table, row_type=row_cls)
