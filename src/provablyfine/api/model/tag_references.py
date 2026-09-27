"""Grants that use a tag id to decide who matches, or to scope what tag ids a permission covers.

A grant of type `identity` or `ssh` can have a `filter.tag_id_list`: an AND of tags the target
identity must hold. Shrinking that list in place would change who the grant matches, since a
filter nobody can currently satisfy would suddenly become satisfiable by whoever holds the
remaining tags, the moment the dead id is dropped. So a grant whose filter names the tag is
removed whole, the same way `identity_references` removes a grant that names a deleted identity.

A grant of type `identity` can also have `permission.add_tag_id_list`, `permission.del_tag_id_list`,
or `permission.create.allowed_tag_id_list`. These are plain allow-sets, not AND-filters. Dropping
one dead id from one of these changes nothing about the other ids in the same list, so it is
edited in place instead of dropping the whole grant.

A grant of type `tag` can have `filter.id`: not a filter that matches identities by tag, but a
permission about managing this one tag object (for example "may delete this tag"). It plays no
part in whether a deletion is refused, since it changes nothing about how anybody else's tags are
matched. But once the tag is gone, it is exactly as dead as the other two kinds, and left alone it
would render as an `InvalidGrant` on read. So it's dropped whole too, on the way out.

The grants live in the `role` and `boundary` tables, in JSON columns, so the database cannot
cascade to them. We do it here.
"""

import dataclasses
import typing

from ... import _sentinel
from . import audit_log, boundary, grant, role


@dataclasses.dataclass(frozen=True)
class Owner:
    """A role or a boundary that holds a grant naming a tag."""

    type: typing.Literal["role", "boundary"]
    id: int
    name: str


def _filter_names(g: grant.Grant, tag_id: int) -> bool:
    return isinstance(g, grant.TripletGrant) and g.filter.tag_id_list is not None and tag_id in g.filter.tag_id_list


def _permission_names(g: grant.Grant, tag_id: int) -> bool:
    if not isinstance(g, grant.IdentityGrant):
        return False
    p = g.permission
    if p.add_tag_id_list is not None and tag_id in p.add_tag_id_list:
        return True
    if p.del_tag_id_list is not None and tag_id in p.del_tag_id_list:
        return True
    return p.create is not None and p.create.allowed_tag_id_list is not None and tag_id in p.create.allowed_tag_id_list


def _tag_object_names(g: grant.Grant, tag_id: int) -> bool:
    return isinstance(g, grant.TagGrant) and g.filter.id == tag_id


def _references(g: grant.Grant, tag_id: int) -> bool:
    """Whether this grant's matching behavior depends on the tag id. Used to decide whether to refuse deletion."""
    return _filter_names(g, tag_id) or _permission_names(g, tag_id)


def _names(g: grant.Grant, tag_id: int) -> bool:
    """Whether this grant mentions the tag id at all, including a `TagGrant` about the tag object itself.

    Used only for cleanup: a `TagGrant` on `filter.id` never affects the refusal decision.
    """
    return _references(g, tag_id) or _tag_object_names(g, tag_id)


def _without_tag(g: grant.IdentityGrant, tag_id: int) -> grant.IdentityGrant:
    """Drop the tag id from a grant's permission allow-lists. Keep everything else."""
    p = g.permission
    update: dict[str, object] = {}
    if p.add_tag_id_list is not None and tag_id in p.add_tag_id_list:
        update["add_tag_id_list"] = [t for t in p.add_tag_id_list if t != tag_id]
    if p.del_tag_id_list is not None and tag_id in p.del_tag_id_list:
        update["del_tag_id_list"] = [t for t in p.del_tag_id_list if t != tag_id]
    if p.create is not None and p.create.allowed_tag_id_list is not None and tag_id in p.create.allowed_tag_id_list:
        update["create"] = p.create.model_copy(
            update={"allowed_tag_id_list": [t for t in p.create.allowed_tag_id_list if t != tag_id]}
        )
    return g.model_copy(update={"permission": p.model_copy(update=update)})


def _rewrite(grants: list[grant.Grant], tag_id: int) -> list[grant.Grant]:
    """Drop grants whose filter (or `TagGrant.filter.id`) names the tag id. Edit in place the ones whose
    permission allow-list does."""
    rewritten: list[grant.Grant] = []
    for g in grants:
        if _filter_names(g, tag_id) or _tag_object_names(g, tag_id):
            continue
        if _permission_names(g, tag_id):
            assert isinstance(g, grant.IdentityGrant)
            rewritten.append(_without_tag(g, tag_id))
        else:
            rewritten.append(g)
    return rewritten


def find(tag_id: int) -> list[Owner]:
    owners: list[Owner] = []
    for r in role.read_all():
        if any(_references(g, tag_id) for g in r.grant_list):
            owners.append(Owner("role", r.id, r.name))
    for b in boundary.read_all():
        grants = b.denied_list + (b.ceiling_list or [])
        if any(_references(g, tag_id) for g in grants):
            owners.append(Owner("boundary", b.id, b.name))
    return owners


def remove(tag_id: int) -> list[Owner]:
    """Remove or rewrite the grants that name the tag id, and return the roles and boundaries that changed.

    A grant whose filter requires the tag id is dropped whole: see the module docstring for why
    it can't just be shrunk. A grant whose permission only lists the tag id in an allow-set keeps
    everything else and just drops that one id.

    A ceiling that loses its last grant becomes `[]`, which denies everything. It must never
    become `None`, which means there is no ceiling.

    Each list that changes gets an audit entry with the grants as they were, before the change,
    that named the tag id. That is all that is needed to put a removed deny rule back, or to
    re-add a dropped tag id to an allow-list.

    Nothing here takes a row lock ahead of reading. `identity_references.remove()`, which this
    mirrors, has the same gap: a concurrent write to the same role or boundary between the read
    and the write can be lost. Closing that is out of scope for this function.
    """
    changes: list[tuple[Owner, str, list[grant.Grant]]] = []
    for r in role.read_all():
        referencing = [g for g in r.grant_list if _names(g, tag_id)]
        if not referencing:
            continue
        role.update(r.id, grant_list=_rewrite(r.grant_list, tag_id))
        changes.append((Owner("role", r.id, r.name), "grant_list", referencing))
    for b in boundary.read_all():
        denied_referencing = [g for g in b.denied_list if _names(g, tag_id)]
        ceiling_referencing = [g for g in b.ceiling_list or [] if _names(g, tag_id)]
        if not denied_referencing and not ceiling_referencing:
            continue
        boundary.update(
            b.id,
            denied_list=_rewrite(b.denied_list, tag_id) if denied_referencing else _sentinel.UNSET,
            ceiling_list=_rewrite(b.ceiling_list or [], tag_id) if ceiling_referencing else _sentinel.UNSET,
        )
        owner = Owner("boundary", b.id, b.name)
        if denied_referencing:
            changes.append((owner, "denied_list", denied_referencing))
        if ceiling_referencing:
            changes.append((owner, "ceiling_list", ceiling_referencing))
    for owner, list_name, referencing in changes:
        audit_log.create(
            "tag-delete-cascade",
            tag_id=tag_id,
            owner_type=owner.type,
            owner_id=owner.id,
            owner_name=owner.name,
            list=list_name,
            affected_grants=[grant.serialize(g) for g in referencing],
        )
    return list(dict.fromkeys(owner for owner, _, _ in changes))
