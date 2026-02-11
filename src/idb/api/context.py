import contextvars
import contextlib
import typing

import cryptography.fernet

from . import dao_factory
from . import config as config_module

_kek_var : contextvars.ContextVar[cryptography.fernet.Fernet] = contextvars.ContextVar("kek", default=None)
_config_var : contextvars.ContextVar[config_module.Config] = contextvars.ContextVar("config", default=None)
_db_var: contextvars.ContextVar[typing.Any] = contextvars.ContextVar("db", default=None)
_identity_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("identity_id", default=None)


class RequestContext:
    """A proxy that makes contextvars feel like regular attributes."""
   
    @property
    def config(self) -> config_module.Config:
        return _config_var.get()

    @property
    def kek(self) -> cryptography.fernet.Fernet:
        return _kek_var.get()

    @property
    def db(self) -> dao_factory.Dao:
        return _db_var.get()

    @property
    def identity_id(self) -> int:
        return _identity_id_var.get()

    @contextlib.contextmanager
    def set_kek(self, kek: cryptography.fernet.Fernet) -> contextvars.Token:
        token = _kek_var.set(kek)
        yield
        _kek_var.reset(token)

    @contextlib.contextmanager
    def set_config(self, config: config_module.Config) -> contextvars.Token:
        token = _config_var.set(config)
        yield
        _config_var.reset(token)

    @contextlib.contextmanager
    def set_db(self, db: dao_factory.Dao) -> contextvars.Token:
        token = _db_var.set(db)
        yield
        _db_var.reset(token)

    @contextlib.contextmanager
    def set_identity_id(self, identity_id: int) -> contextvars.Token:
        token = _identity_id_var.set(identity_id)
        yield
        _identity_id_var.reset(token)


ctx = RequestContext()
