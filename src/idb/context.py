import contextvars
import typing

import cryptography.fernet

from . import dao_factory
from . import config

_kek_var : contextvars.ContextVar[cryptography.fernet.Fernet] = contextvars.ContextVar("kek", default=None)
_config_var : contextvars.ContextVar[config.Config] = contextvars.ContextVar("config", default=None)
_db_var: contextvars.ContextVar[typing.Any] = contextvars.ContextVar("db", default=None)
_identity_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("identity_id", default=None)


class RequestContext:
    """A proxy that makes contextvars feel like regular attributes."""
   
    @property
    def config(self) -> config.Config:
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

    def set_kek(self, kek: cryptography.fernet.Fernet) -> contextvars.Token:
        return _kek_var.set(kek)

    def set_config(self, config: config.Config) -> contextvars.Token:
        return _config_var.set(config)

    def set_db(self, db: dao_factory.Dao) -> contextvars.Token:
        return _db_var.set(db)

    def set_identity_id(self, identity_id: int) -> contextvars.Token:
        return _identity_id_var.set(identity_id)


ctx = RequestContext()
