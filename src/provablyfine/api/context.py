import collections.abc
import contextlib
import contextvars
import dataclasses

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
_tenant_uuid_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("tenant_uuid", default=None)


@dataclasses.dataclass
class Deferred:
    """Work that waits for the end of the request's tenant transaction."""

    after_commit: list[collections.abc.Callable[[], None]] = dataclasses.field(
        default_factory=list[collections.abc.Callable[[], None]]
    )
    after_rollback: list[collections.abc.Callable[[], None]] = dataclasses.field(
        default_factory=list[collections.abc.Callable[[], None]]
    )


_deferred_var: contextvars.ContextVar[Deferred | None] = contextvars.ContextVar("deferred", default=None)


class RequestContext:
    """A proxy that makes contextvars feel like regular attributes."""

    def after_commit(self, action: collections.abc.Callable[[], None]) -> None:
        """Run `action` once the request's transaction has committed, before the response is sent.

        Use it for anything that must not happen if the request fails, and must not hold the database lock.
        Examples are sending an email or calling another service.
        The action runs in a worker thread and has no database access.
        If it raises a `ProblemHTTPException`, the client gets that error.
        """
        deferred = _deferred_var.get()
        assert deferred is not None
        deferred.after_commit.append(action)

    def after_rollback(self, action: collections.abc.Callable[[], None]) -> None:
        """Run `action` if the request is rejected with a `ProblemHTTPException`, after its rollback.

        The action runs in its own transaction, so what it writes survives the rejection.
        Capture what you need from the request when you schedule it.
        """
        deferred = _deferred_var.get()
        assert deferred is not None
        deferred.after_rollback.append(action)

    @contextlib.contextmanager
    def set_deferred(self, deferred: Deferred):
        assert _deferred_var.get() is None
        _deferred_var.set(deferred)
        try:
            yield
        finally:
            _deferred_var.set(None)

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
    def tenant_uuid(self) -> str:
        v = _tenant_uuid_var.get()
        assert v is not None
        return v

    @contextlib.contextmanager
    def set_tenant_uuid(self, tenant_uuid: str):
        assert _tenant_uuid_var.get() is None
        _tenant_uuid_var.set(tenant_uuid)
        try:
            yield
        finally:
            _tenant_uuid_var.set(None)


ctx = RequestContext()
