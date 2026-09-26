"""Pytest-native selection of which database backends to test against.

Most tests only run against SQLite, the default and the fast path for local
iteration. A small, curated set of tests that specifically exercise SQL
portability request the `db_backend` fixture; which backends they actually
run against is controlled by `--db-backends`. Tests that never request
`db_backend` are completely unaffected: no extra parametrization, and no
Postgres/MySQL container ever starts.

This lives at the repo root, rather than in tests/conftest.py, so that
`--db-backends` is registered regardless of which subtree pytest is invoked
against (e.g. `pytest src/provablyfine/api/test_migrate.py` alone).
"""

import dataclasses
import pathlib
import secrets
import time
import typing

import pytest
import sqlalchemy

import provablyfine.api.db
import tests.conftest

_ALL_BACKENDS = ("sqlite", "postgres", "mysql")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--db-backends",
        action="store",
        default="sqlite",
        help=(
            "Comma-separated database backends for multi-backend tests: "
            "sqlite,postgres,mysql, or 'all'. Tests that don't request the "
            "db_backend fixture are unaffected. Default: sqlite only."
        ),
    )


def _requested_backends(config: pytest.Config) -> tuple[str, ...]:
    raw = config.getoption("--db-backends")
    if raw == "all":
        return _ALL_BACKENDS
    names = tuple(b.strip() for b in raw.split(",") if b.strip())
    unknown = set(names) - set(_ALL_BACKENDS)
    if unknown:
        raise pytest.UsageError(
            f"Unknown --db-backends value(s): {sorted(unknown)}. Choose from {_ALL_BACKENDS} or 'all'."
        )
    return names


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "db_backend" in metafunc.fixturenames:
        backends = _requested_backends(metafunc.config)
        metafunc.parametrize("db_backend", backends, indirect=True, ids=list(backends))


@dataclasses.dataclass(frozen=True)
class DbBackend:
    """A database backend to provision fresh, throwaway databases against, for one test."""

    name: str
    admin_url: str | None  # None for sqlite

    def fresh_database_url(self, request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> str:
        """A fresh, empty database URL, dropped after the test.

        Schema-agnostic: what schema ends up in it depends on which migration the test
        runs against it (registry or tenant), not on this method.

        For a shared-server backend, this is exactly the create_database/derive_tenant_url
        machinery that production tenant provisioning uses (see db.py, endpoints/tenant.py):
        test-side and production code share it rather than each having their own.
        """
        if self.name == "sqlite":
            return f"sqlite:///{tmp_path / 'tenants.db'}"
        assert self.admin_url is not None
        made = sqlalchemy.make_url(self.admin_url)
        db_name = f"pf_test_{secrets.token_hex(8)}"
        url = made.set(database=db_name).render_as_string(hide_password=False)
        provablyfine.api.db.create_database(url)
        request.addfinalizer(lambda: provablyfine.api.db.drop_database(url))
        return url


@pytest.fixture(scope="session")
def db_backend(request: pytest.FixtureRequest) -> DbBackend:
    name = request.param
    if name == "sqlite":
        return DbBackend(name="sqlite", admin_url=None)
    if name == "postgres":
        container = request.getfixturevalue("postgres_container")
    elif name == "mysql":
        container = request.getfixturevalue("mysql_container")
    else:
        raise AssertionError(f"Unknown db_backend param {name!r}")
    return DbBackend(name=name, admin_url=container.admin_url)


@dataclasses.dataclass(frozen=True)
class _DbContainer:
    container_id: str
    admin_url: str


def _run_db_container(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    *,
    image: str,
    env: dict[str, str],
    admin_url_template: str,
) -> typing.Generator[_DbContainer, None, None]:
    """Run a stock database server image and wait until it accepts real connections.

    Unlike sshd's readiness probe (a raw TCP connect), this needs to actually run a
    query: Postgres and MariaDB both accept TCP connections partway through startup,
    before they can authenticate or run anything.
    """
    tests.conftest._require_podman()
    tmp_path = tmp_path_factory.getbasetemp()
    args = ["podman", "run", "--detach", "--quiet", "--publish-all"]
    for k, v in env.items():
        args += ["--env", f"{k}={v}"]
    args.append(image)
    stdout = tests.conftest._run(args, tmp_path)
    container_id = stdout.strip("\n")
    stdout = tests.conftest._run(["podman", "port", container_id], tmp_path)
    try:
        port = tests.conftest._parse_port_mapping(stdout)
    except Exception:
        print(f"Database container: {container_id}")
        raise

    deadline = time.monotonic() + 60  # Postgres/MariaDB cold start is slower than sshd's
    last_error: Exception | None = None
    admin_url: str | None = None
    while time.monotonic() < deadline and admin_url is None:
        # 169.254.0.1 is the podman host address seen from within a sandbox isolated
        # from the host; 127.0.0.1 is the normal case.
        for address in ["127.0.0.1", "169.254.0.1"]:
            candidate = admin_url_template.format(address=address, port=port)
            engine = sqlalchemy.create_engine(candidate, connect_args={"connect_timeout": 2})
            try:
                with engine.connect() as conn:
                    conn.exec_driver_sql("SELECT 1")
                admin_url = candidate
                break
            except Exception as e:
                last_error = e
            finally:
                engine.dispose()
        if admin_url is None:
            time.sleep(0.5)
    if admin_url is None:
        print(f"Database container: {container_id}")
        raise Exception(f"database container {container_id} not ready after 60s: {last_error}")

    try:
        yield _DbContainer(container_id=container_id, admin_url=admin_url)
    finally:
        tests.conftest._run(["podman", "container", "stop", "-t", "0", container_id], tmp_path)


@pytest.fixture(scope="session")
def postgres_container(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> typing.Generator[_DbContainer, None, None]:
    yield from _run_db_container(
        request,
        tmp_path_factory,
        image="docker.io/library/postgres:17-alpine",
        env={"POSTGRES_PASSWORD": "pf-test", "POSTGRES_USER": "postgres"},
        admin_url_template="postgresql+psycopg://postgres:pf-test@{address}:{port}/postgres",
    )


@pytest.fixture(scope="session")
def mysql_container(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> typing.Generator[_DbContainer, None, None]:
    yield from _run_db_container(
        request,
        tmp_path_factory,
        image="docker.io/library/mariadb:11",
        env={"MARIADB_ROOT_PASSWORD": "pf-test"},
        admin_url_template="mysql+pymysql://root:pf-test@{address}:{port}/",
    )
