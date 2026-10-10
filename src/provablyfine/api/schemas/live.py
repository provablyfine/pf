from __future__ import annotations

import typing

import pydantic

from . import base

_CONNECTION_ID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class LiveSession(base.APIBase):
    id: str
    connection_id: str
    identity_id: int
    hostname: str
    kind: typing.Literal["relay", "host"]
    session_id: str
    started_at: int
    ended_at: int | None
    deadline: int | None


class LiveListResponse(base.APIBase):
    sessions: list[LiveSession] = pydantic.Field(default_factory=list[LiveSession])


class LiveReportRequest(base.APIBase):
    """A host or a relay reports that a session started or ended."""

    connection_id: str = pydantic.Field(pattern=_CONNECTION_ID)
    kind: typing.Literal["relay", "host"]
    # The session id on the host. Empty when the reporter has none.
    session_id: str = pydantic.Field(default="", max_length=64, pattern=r"^[0-9A-Za-z._-]*$")
    # When it happened, in seconds since the epoch.
    at: int = pydantic.Field(ge=0)
