import contextlib
import contextvars

import cryptography.fernet

from . import app_db as app_db_module
from . import config as config_module

_kek_var: contextvars.ContextVar[cryptography.fernet.Fernet | None] = contextvars.ContextVar("kek", default=None)
_config_var: contextvars.ContextVar[config_module.Config | None] = contextvars.ContextVar("config", default=None)
_app_db_var: contextvars.ContextVar[app_db_module.AppDb | None] = contextvars.ContextVar("app_db", default=None)
_identity_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar("identity_id", default=None)
_active_role_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar("active_role_id", default=None)
_session_key_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("session_key_id", default=None)
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
    def app_db(self) -> app_db_module.AppDb:
        db = _app_db_var.get()
        assert db is not None
        return db

    @property
    def identity_id(self) -> int | None:
        return _identity_id_var.get()

    @property
    def active_role_id(self) -> int | None:
        return _active_role_id_var.get()

    @property
    def session_key_id(self) -> str | None:
        return _session_key_id_var.get()

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
    def set_app_db(self, app_db: app_db_module.AppDb):
        assert _app_db_var.get() is None
        _app_db_var.set(app_db)
        try:
            yield
        finally:
            _app_db_var.set(None)

    @contextlib.contextmanager
    def set_identity_id(self, identity_id: int):
        assert _identity_id_var.get() is None
        _identity_id_var.set(identity_id)
        try:
            yield
        finally:
            _identity_id_var.set(None)

    @contextlib.contextmanager
    def set_active_role_id(self, role_id: int | None):
        token = _active_role_id_var.set(role_id)
        try:
            yield
        finally:
            _active_role_id_var.reset(token)

    @contextlib.contextmanager
    def set_session_key_id(self, key_id: str):
        assert _session_key_id_var.get() is None
        _session_key_id_var.set(key_id)
        try:
            yield
        finally:
            _session_key_id_var.set(None)

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
