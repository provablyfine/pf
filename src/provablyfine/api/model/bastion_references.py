"""The grants that name a bastion.

A grant of type `bastion` has a filter with an `id`. It is about that one bastion.
Once the bastion is deleted, ids are never reused, so such a grant can never match anything again.
Deleting the bastion cannot change what anybody else is allowed to do.

The grants live in the `role` and `boundary` tables, in JSON columns, so the database cannot cascade to them.
We do it here.
"""

import dataclasses
import typing

from ... import _sentinel
from . import audit_log, boundary, grant, role


@dataclasses.dataclass(frozen=True)
class Owner:
    """A role or a boundary that holds a grant naming a bastion."""

    type: typing.Literal["role", "boundary"]
    id: int
    name: str


def _names(g: grant.Grant, bastion_id: int) -> bool:
    return isinstance(g, grant.BastionGrant) and g.filter.id == bastion_id


def _without(grants: list[grant.Grant], bastion_id: int) -> list[grant.Grant]:
    """Drop whole grants. Never edit a grant: a filter list emptied by hand matches everything."""
    return [g for g in grants if not _names(g, bastion_id)]


def find(bastion_id: int) -> list[Owner]:
    owners: list[Owner] = []
    for r in role.read_all():
        if any(_names(g, bastion_id) for g in r.grant_list):
            owners.append(Owner("role", r.id, r.name))
    for b in boundary.read_all():
        grants = b.denied_list + (b.ceiling_list or [])
        if any(_names(g, bastion_id) for g in grants):
            owners.append(Owner("boundary", b.id, b.name))
    return owners


def remove(bastion_id: int) -> list[Owner]:
    """Remove the grants that name the bastion, and return the roles and boundaries that changed.

    Everything else in a role or a boundary is kept as it is.
    A ceiling that loses its last grant becomes `[]`, which denies everything. It must never become `None`,
    which means that there is no ceiling.

    Each list that changes gets an audit entry with the grants that were removed.
    That is all that is needed to put a removed deny rule back.

    On a database without serialized writers, reading a list and writing it back needs a row lock.
    """
    changes: list[tuple[Owner, str, list[grant.Grant]]] = []
    for r in role.read_all():
        removed = [g for g in r.grant_list if _names(g, bastion_id)]
        if not removed:
            continue
        role.update(r.id, grant_list=_without(r.grant_list, bastion_id))
        changes.append((Owner("role", r.id, r.name), "grant_list", removed))
    for b in boundary.read_all():
        denied_removed = [g for g in b.denied_list if _names(g, bastion_id)]
        ceiling_removed = [g for g in b.ceiling_list or [] if _names(g, bastion_id)]
        if not denied_removed and not ceiling_removed:
            continue
        boundary.update(
            b.id,
            denied_list=_without(b.denied_list, bastion_id) if denied_removed else _sentinel.UNSET,
            ceiling_list=_without(b.ceiling_list or [], bastion_id) if ceiling_removed else _sentinel.UNSET,
        )
        owner = Owner("boundary", b.id, b.name)
        if denied_removed:
            changes.append((owner, "denied_list", denied_removed))
        if ceiling_removed:
            changes.append((owner, "ceiling_list", ceiling_removed))
    for owner, list_name, removed in changes:
        audit_log.create(
            "bastion-delete-cascade",
            bastion_id=bastion_id,
            owner_type=owner.type,
            owner_id=owner.id,
            owner_name=owner.name,
            list=list_name,
            removed_grants=[grant.serialize(g) for g in removed],
        )
    return list(dict.fromkeys(owner for owner, _, _ in changes))
