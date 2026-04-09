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
_tenant_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar("tenant_id", default=None)
_tenant_name_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("tenant_name", default=None)


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
        assert _kek_var.get() is None
        _kek_var.set(kek)
        try:
            yield
        finally:
            _kek_var.set(None)

    @contextlib.contextmanager
    def set_config(self, config: config_module.Config):
        assert _config_var.get() is None
        _config_var.set(config)
        try:
            yield
        finally:
            _config_var.set(None)

    @contextlib.contextmanager
    def set_db(self, db: dao_factory.Dao):
        assert _db_var.get() is None
        _db_var.set(db)
        try:
            yield
        finally:
            _db_var.set(None)

    @contextlib.contextmanager
    def set_identity_id(self, identity_id: int):
        assert _identity_id_var.get() is None
        _identity_id_var.set(identity_id)
        try:
            yield
        finally:
            _identity_id_var.set(None)

    @property
    def tenant_id(self) -> int:
        v = _tenant_id_var.get()
        assert v is not None
        return v

    @contextlib.contextmanager
    def set_tenant_id(self, tenant_id: int):
        assert _tenant_id_var.get() is None
        _tenant_id_var.set(tenant_id)
        try:
            yield
        finally:
            _tenant_id_var.set(None)

    @property
    def tenant_name(self) -> str:
        v = _tenant_name_var.get()
        assert v is not None
        return v

    @contextlib.contextmanager
    def set_tenant_name(self, tenant_name: str):
        assert _tenant_name_var.get() is None
        _tenant_name_var.set(tenant_name)
        try:
            yield
        finally:
            _tenant_name_var.set(None)


ctx = RequestContext()
