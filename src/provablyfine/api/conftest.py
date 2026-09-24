import collections.abc
import pathlib
import typing

import cryptography.fernet
import pytest

from . import app_db, db, migrate
from .context import ctx

if typing.TYPE_CHECKING:
    import conftest as root_conftest


@pytest.fixture
def tenant_app_db(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> collections.abc.Iterator[app_db.AppDb]:
    """A real, migrated tenant database inside one write transaction, wired into ctx.

    The correctness these tests check (conditional updates, unique constraints) must
    hold on every backend, not just SQLite, so this runs against whichever backend(s)
    --db-backends selected; see the repo-root conftest.py.
    """
    url = db_backend.fresh_database_url(request, tmp_path)
    migrate.create_tenant(url)
    engine = db.create_engine(url)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection:
        application_db = app_db.create(connection)
        with ctx.set_app_db(application_db), ctx.set_kek(kek):
            yield application_db
