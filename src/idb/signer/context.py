import contextvars
import contextlib
import typing

import cryptography.fernet

from . import config as config_module

_kek_var : contextvars.ContextVar[cryptography.fernet.Fernet] = contextvars.ContextVar("kek", default=None)
_config_var : contextvars.ContextVar[config_module.Config] = contextvars.ContextVar("config", default=None)


class RequestContext:
    """A proxy that makes contextvars feel like regular attributes."""
   
    @property
    def config(self) -> config_module.Config:
        return _config_var.get()

    @property
    def kek(self) -> cryptography.fernet.Fernet:
        return _kek_var.get()

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


ctx = RequestContext()
