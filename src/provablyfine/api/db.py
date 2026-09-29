from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import os
import re
import sqlite3
import threading

import sqlalchemy
import sqlalchemy.event
import sqlalchemy.exc
import sqlalchemy.pool


def create_engine(
    url: str,
    echo: bool = False,
    *,
    pool_size: int | None = None,
    max_overflow: int | None = None,
    pool_per_use: bool = False,
) -> sqlalchemy.Engine:
    """Create an engine whose transactions are real transactions.

    With the sqlite3 driver's default mode, a transaction only starts at the first INSERT,
    UPDATE or DELETE. SELECT and DDL statements run outside of any transaction.
    Here the driver never starts transactions and SQLAlchemy sends BEGIN itself.
    Everything up to the commit is one transaction.

    `pool_size` and `max_overflow` bound the connections of this engine.
    `pool_per_use` opens a connection for each transaction and closes it right after.
    It suits a sqlite file that is used rarely: an idle engine then holds nothing.

    Use `begin()` to start a transaction.
    """
    pool_options: dict[str, object] = {}
    if pool_per_use:
        pool_options["poolclass"] = sqlalchemy.pool.NullPool
    else:
        if pool_size is not None:
            pool_options["pool_size"] = pool_size
        if max_overflow is not None:
            pool_options["max_overflow"] = max_overflow
    engine = sqlalchemy.create_engine(url, echo=echo, **pool_options)
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


class TenantDatabases:
    """The databases of all the tenants. Create one for the whole process and share it.

    On sqlite each tenant is a file of its own, with an engine of its own.
    An engine opens a connection for each transaction, so an idle tenant holds nothing.

    On Postgres and MySQL all the tenants share the registry's server.
    Each tenant is a schema. On MySQL a schema is a database.
    They also share one engine, so `pool_size` and `max_overflow` bound the connections of all of them.
    Every statement sent through the engine of a tenant is qualified as "schema"."table".
    The tables are declared without a schema and exist only in the tenant schemas.
    A statement sent through the shared engine itself fails instead of reaching another tenant.
    """

    def __init__(
        self,
        registry_url: str,
        *,
        echo: bool = False,
        pool_size: int | None = None,
        max_overflow: int | None = None,
    ) -> None:
        self._registry_url = registry_url
        self._echo = echo
        self._lock = threading.Lock()
        self._files: dict[str, sqlalchemy.Engine] = {}
        self._server: sqlalchemy.Engine | None = None
        if not is_sqlite(registry_url):
            self._server = create_engine(registry_url, echo=echo, pool_size=pool_size, max_overflow=max_overflow)

    @property
    def registry_url(self) -> str:
        return self._registry_url

    def _locate(self, tenant_uuid: str) -> tuple[str, str | None]:
        """The URL to connect to and the schema in it. The schema is None on sqlite.

        The schema is named after the registry database, so that two registries sharing one
        physical server (e.g. two test runs against the same container) never collide on
        the same tenant schema name. For sqlite, a tenant is one file, named after the
        tenant, in a "tenants" directory next to the registry's own file.
        """
        made_url = sqlalchemy.make_url(self._registry_url)
        dialect = made_url.get_backend_name()
        suffix = tenant_uuid.replace("-", "")
        if dialect == "sqlite":
            return f"sqlite:///{os.path.join(_sqlite_tenants_dir(self._registry_url), f'{suffix}.db')}", None
        registry_name = made_url.database
        assert registry_name is not None
        schema = f"{registry_name}_t_{suffix}"
        _validate_database_name(schema, dialect)
        return self._registry_url, schema

    def create(self, tenant_uuid: str) -> str:
        """Create the empty schema of a tenant. On sqlite, create the directory of its file.

        Returns the URL to record in the registry. It never holds a password.
        """
        url, schema = self._locate(tenant_uuid)
        made_url = sqlalchemy.make_url(url)
        if schema is None:
            create_database(url)
        elif made_url.get_backend_name() == "postgresql":
            engine = sqlalchemy.create_engine(made_url, isolation_level="AUTOCOMMIT")
            try:
                with engine.connect() as conn:
                    conn.exec_driver_sql(f"CREATE SCHEMA {conn.dialect.identifier_preparer.quote_schema(schema)}")
            finally:
                engine.dispose()
        else:
            create_database(made_url.set(database=schema).render_as_string(hide_password=False))
        return made_url.render_as_string(hide_password=True)

    def delete(self, tenant_uuid: str) -> None:
        """Drop the schema of a tenant with everything in it. On sqlite, forget the engine of its file.

        The connections of the shared engine are not in the schema, so nothing has to be disposed first.
        """
        url, schema = self._locate(tenant_uuid)
        made_url = sqlalchemy.make_url(url)
        if schema is None:
            with self._lock:
                engine = self._files.pop(tenant_uuid, None)
            if engine is not None:
                engine.dispose()
        elif made_url.get_backend_name() == "postgresql":
            admin = sqlalchemy.create_engine(made_url, isolation_level="AUTOCOMMIT")
            try:
                with admin.connect() as conn:
                    conn.exec_driver_sql(
                        f"DROP SCHEMA IF EXISTS {conn.dialect.identifier_preparer.quote_schema(schema)} CASCADE"
                    )
            finally:
                admin.dispose()
        else:
            drop_database(made_url.set(database=schema).render_as_string(hide_password=False))

    def engine(self, tenant_uuid: str) -> sqlalchemy.Engine:
        """The engine to use for one tenant. Pass it to `begin` or `abegin`."""
        url, schema = self._locate(tenant_uuid)
        if schema is not None:
            assert self._server is not None
            return self._server.execution_options(schema_translate_map={None: schema})
        with self._lock:
            if tenant_uuid not in self._files:
                self._files[tenant_uuid] = create_engine(url, echo=self._echo, pool_per_use=True)
            return self._files[tenant_uuid]

    def migration_engine(self, tenant_uuid: str) -> sqlalchemy.Engine:
        """An engine whose connections work inside the tenant's schema without qualifying names.

        For Alembic and reflection only. The caller disposes it.
        Alembic writes its own DDL and does not honor the schema translate map that `engine` uses.
        Here the connection itself is pointed at the schema.
        Postgres takes a search path. MySQL takes a default database.
        """
        url, schema = self._locate(tenant_uuid)
        made_url = sqlalchemy.make_url(url)
        connect_args: dict[str, object] = {}
        if schema is None:
            connect_args["autocommit"] = False
        elif made_url.get_backend_name() == "postgresql":
            connect_args["options"] = f"-csearch_path={schema}"
        else:
            made_url = made_url.set(database=schema)
        return sqlalchemy.create_engine(made_url, poolclass=sqlalchemy.pool.NullPool, connect_args=connect_args)

    def dispose(self) -> None:
        with self._lock:
            engines = list(self._files.values())
            self._files.clear()
        for engine in engines:
            engine.dispose()
        if self._server is not None:
            self._server.dispose()


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
