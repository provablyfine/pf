import contextlib
import contextvars
import typing

import cryptography.fernet

from . import config as config_module
from . import dao_factory

_kek_var: contextvars.ContextVar[cryptography.fernet.Fernet | None] = contextvars.ContextVar("kek", default=None)
_config_var: contextvars.ContextVar[config_module.Config | None] = contextvars.ContextVar("config", default=None)
_db_var: contextvars.ContextVar[typing.Any | None] = contextvars.ContextVar("db", default=None)
_identity_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar("identity_id", default=None)


class RequestContext:
    """A proxy that makes contextvars feel like regular attributes."""

    @property
    def config(self) -> config_module.Config:
        c = _config_var.get()
        assert c is not None
        return c

    @property
    def kek(self) -> cryptography.fernet.Fernet:
        key = _kek_var.get()
        assert key is not None
        return key

    @property
    def db(self) -> dao_factory.Dao:
        dao = _db_var.get()
        assert dao is not None
        return dao

    @property
    def identity_id(self) -> int | None:
        return _identity_id_var.get()

    @contextlib.contextmanager
    def set_kek(self, kek: cryptography.fernet.Fernet):
        token = _kek_var.set(kek)
        yield
        _kek_var.reset(token)

    @contextlib.contextmanager
    def set_config(self, config: config_module.Config):
        token = _config_var.set(config)
        yield
        _config_var.reset(token)

    @contextlib.contextmanager
    def set_db(self, db: dao_factory.Dao):
        token = _db_var.set(db)
        yield
        _db_var.reset(token)

    @contextlib.contextmanager
    def set_identity_id(self, identity_id: int):
        token = _identity_id_var.set(identity_id)
        yield
        _identity_id_var.reset(token)


ctx = RequestContext()
