import collections.abc
import pathlib

import cryptography.fernet
import pytest

from . import app_db, db, migrate
from .context import ctx


@pytest.fixture
def tenant_app_db(tmp_path: pathlib.Path) -> collections.abc.Iterator[app_db.AppDb]:
    """A real, migrated tenant database inside one write transaction, wired into ctx."""
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    migrate.create_tenant(url)
    engine = db.create_engine(url)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection:
        application_db = app_db.create(connection)
        with ctx.set_app_db(application_db), ctx.set_kek(kek):
            yield application_db
