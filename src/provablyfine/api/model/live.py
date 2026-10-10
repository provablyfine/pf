"""The registry of sessions seen by the bastion relay and by hosts.

A report names a connection id. The certificate record made at signing time says who the connection
belongs to and which host it is for, so a host can only report connections that were issued for it.
"""

import time
import typing
import uuid

from .. import app_db
from ..context import ctx

# Certificate records are kept this long after the certificate expires.
# A host that was offline can still report a session it saw, until then.
CONNECTION_RETENTION_S = 24 * 3600

Kind = typing.Literal["relay", "host"]


class UnknownConnection(Exception):
    """The connection id is not known, or was not issued for this host."""


def _connection(connection_id: str, hostname: str) -> app_db.SshConnectionRow:
    row = ctx.app_db.ssh_connection.read_one(connection_id=connection_id)
    if row is None or row.hostname != hostname:
        raise UnknownConnection(connection_id)
    return row


def start(*, connection_id: str, hostname: str, kind: Kind, session_id: str, at: int) -> None:
    """Record that a session started. Reporting the same session again changes nothing."""
    row = _connection(connection_id, hostname)
    ctx.app_db.live_session.create_if_absent(
        id=str(uuid.uuid4()),
        connection_id=connection_id,
        identity_id=row.identity_id,
        hostname=hostname,
        kind=kind,
        session_id=session_id,
        started_at=at,
        ended_at=None,
        deadline=row.deadline,
    )


def end(*, connection_id: str, hostname: str, kind: Kind, session_id: str, at: int) -> None:
    """Record that a session ended. A session that already ended keeps its first end time.

    An empty session id ends every open session of this connection that the host reported.
    """
    _connection(connection_id, hostname)
    table = ctx.app_db.live_session
    columns = table.columns
    where: dict[str, typing.Any] = {"connection_id": connection_id, "kind": kind, "hostname": hostname}
    if session_id != "":
        where["session_id"] = session_id
    rows = table.read_all(columns.ended_at.is_(None), **where)
    for row in rows:
        table.update(ended_at=max(at, row.started_at)).where(id=row.id, ended_at=None)


def read_one(id: str) -> app_db.LiveSessionRow | None:
    return ctx.app_db.live_session.read_one(id=id)


def read_all(
    *, hostname: str | None = None, identity_id: int | None = None, active: bool | None = None
) -> list[app_db.LiveSessionRow]:
    positional: list[typing.Any] = []
    kwargs: dict[str, typing.Any] = {}
    columns = ctx.app_db.live_session.columns
    if hostname is not None:
        kwargs["hostname"] = hostname
    if identity_id is not None:
        kwargs["identity_id"] = identity_id
    if active is True:
        positional.append(columns.ended_at.is_(None))
    elif active is False:
        positional.append(columns.ended_at.is_not(None))
    rows = ctx.app_db.live_session.read_all(*positional, **kwargs)
    return sorted(rows, key=lambda r: (r.started_at, r.id), reverse=True)


def now() -> int:
    return int(time.time())
