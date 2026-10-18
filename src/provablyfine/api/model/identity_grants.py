"""The grants that name an identity.

A grant of type `identity` or `ssh` has a filter with an `id`. It is about that one identity, as a target.
Once the identity is deleted, ids are never reused, so such a grant can never match anything again.
Deleting the identity cannot change what anybody else is allowed to do.

The grants live in the `role` and `boundary` tables, in JSON columns, so the database cannot cascade to them.
We do it here.
"""

import dataclasses
import typing

from ... import _sentinel
from . import boundary, grant, role


@dataclasses.dataclass(frozen=True)
class Owner:
    """A role or a boundary that holds a grant naming an identity."""

    type: typing.Literal["role", "boundary"]
    id: int
    name: str


def _names(g: grant.Grant, identity_id: int) -> bool:
    return isinstance(g, grant.TripletGrant) and g.filter.id == identity_id


def _without(grants: list[grant.Grant], identity_id: int) -> list[grant.Grant]:
    """Drop whole grants. Never edit a grant: a filter list emptied by hand matches everything."""
    return [g for g in grants if not _names(g, identity_id)]


def find(identity_id: int) -> list[Owner]:
    owners: list[Owner] = []
    for r in role.read_all():
        if any(_names(g, identity_id) for g in r.grant_list):
            owners.append(Owner("role", r.id, r.name))
    for b in boundary.read_all():
        grants = b.denied_list + (b.ceiling_list or [])
        if any(_names(g, identity_id) for g in grants):
            owners.append(Owner("boundary", b.id, b.name))
    return owners


def remove(identity_id: int) -> list[Owner]:
    """Remove the grants that name the identity, and return the roles and boundaries that changed.

    Everything else in a role or a boundary is kept as it is.
    A ceiling that loses its last grant becomes `[]`, which denies everything. It must never become `None`,
    which means that there is no ceiling.

    Each role or boundary that changes gets its own update entry, which holds the list as it was.
    That is all that is needed to put a removed deny rule back.
    The caller wraps this in `audit_log.cause` so that each entry names what was deleted.

    On a database without serialized writers, reading a list and writing it back needs a row lock.
    """
    changes: list[Owner] = []
    for r in role.read_all():
        removed = [g for g in r.grant_list if _names(g, identity_id)]
        if not removed:
            continue
        role.update(r.id, grant_list=_without(r.grant_list, identity_id))
        changes.append(Owner("role", r.id, r.name))
    for b in boundary.read_all():
        denied_removed = [g for g in b.denied_list if _names(g, identity_id)]
        ceiling_removed = [g for g in b.ceiling_list or [] if _names(g, identity_id)]
        if not denied_removed and not ceiling_removed:
            continue
        boundary.update(
            b.id,
            denied_list=_without(b.denied_list, identity_id) if denied_removed else _sentinel.UNSET,
            ceiling_list=_without(b.ceiling_list or [], identity_id) if ceiling_removed else _sentinel.UNSET,
        )
        owner = Owner("boundary", b.id, b.name)
        if denied_removed:
            changes.append(owner)
        if ceiling_removed:
            changes.append(owner)
    return list(dict.fromkeys(changes))
