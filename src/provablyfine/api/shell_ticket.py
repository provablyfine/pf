from __future__ import annotations

import dataclasses
import secrets
import time

from .. import jwk
from . import schemas


@dataclasses.dataclass(frozen=True)
class Ticket:
    identity_id: int
    active_role_id: int | None
    hostname: str
    username: str
    connection_id: str
    certificate: bytes
    private_key: jwk.Private
    bastion_list: list[schemas.bastion.Bastion]
    deadline: int | None
    expires_at: int


class ShellTicketStore:
    def __init__(self) -> None:
        self._tickets: dict[str, Ticket] = {}

    def issue(self, ticket: Ticket) -> str:
        ticket_id = secrets.token_urlsafe(32)
        self._tickets[ticket_id] = ticket
        return ticket_id

    def redeem(self, ticket_id: str) -> Ticket | None:
        ticket = self._tickets.pop(ticket_id, None)
        if ticket is None or ticket.expires_at < time.time():
            return None
        return ticket
