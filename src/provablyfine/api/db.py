from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import os
import re
import sqlite3

import sqlalchemy
import sqlalchemy.event
import sqlalchemy.exc


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


def is_sqlite(url: str) -> bool:
    return sqlalchemy.make_url(url).get_backend_name() == "sqlite"


def is_database_busy(exc: sqlalchemy.exc.OperationalError) -> bool:
    """Whether `exc` is sqlite's own error for its whole-file write lock being contended.

    Postgres and MySQL do row-level locking and never raise this from this driver;
    a caller that sees it should treat the database as transiently overloaded.
    """
    return "sqlite3" in type(exc.orig).__module__ and "database is locked" in str(exc.orig)


def violated_unique_column(exc: sqlalchemy.exc.IntegrityError, table: str, column: str) -> bool:
    """Whether `exc` was a UNIQUE constraint violation on `table.column`.

    Each driver reports which column differently. Postgres names the constraint
    itself, deterministically, from a plain `Column(unique=True)` with no explicit
    name (its own auto-naming convention: "{table}_{column}_key"), and exposes it
    structurally via `orig.diag`. SQLite and MySQL/MariaDB report it as part of the
    driver's error message text instead, in their own driver-specific format.
    """
    orig = exc.orig
    diag = getattr(orig, "diag", None)
    constraint_name = getattr(diag, "constraint_name", None) if diag is not None else None
    if constraint_name is not None:
        return constraint_name == f"{table}_{column}_key"
    text = str(orig)
    return f"{table}.{column}" in text or f"'{column}'" in text


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
