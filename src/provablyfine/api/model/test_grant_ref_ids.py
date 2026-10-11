"""`referenced_ids` must read every field of a grant that holds an object id."""

import types
import typing

import pydantic

from . import grant


def _grant_classes() -> list[type[pydantic.BaseModel]]:
    union = typing.get_args(grant.Grant)[0]
    return list(typing.get_args(union))


def _id_paths(model: type[pydantic.BaseModel], prefix: str = "") -> list[str]:
    paths: list[str] = []
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        if name == "id" or name.endswith("_id") or name.endswith("_id_list"):
            paths.append(path)
        for arg in _types_of(field.annotation):
            if isinstance(arg, type) and issubclass(arg, pydantic.BaseModel):
                paths.extend(_id_paths(arg, f"{path}."))
    return paths


def _types_of(annotation: object) -> list[object]:
    if isinstance(annotation, types.UnionType | type(typing.Union[int, str])):  # noqa: UP007
        return list(typing.get_args(annotation))
    return [annotation]


# Every id-like field of a grant, and the RefIds kind that `referenced_ids` files it under.
_COVERED: dict[str, str] = {
    "TagGrant.filter.id": "tag",
    "RoleGrant.filter.id": "role",
    "BoundaryGrant.filter.id": "boundary",
    "BastionGrant.filter.id": "bastion",
    "AuthGrant.filter.id": "auth",
    "TenantGrant.filter.id": "tenant",
    "LiveGrant.filter.tag_id_list": "tag",
    "IdentityGrant.filter.id": "identity",
    "IdentityGrant.filter.tag_id_list": "tag",
    "IdentityGrant.filter.boundary_id_list": "boundary",
    "IdentityGrant.permission.add_tag_id_list": "tag",
    "IdentityGrant.permission.del_tag_id_list": "tag",
    "IdentityGrant.permission.create.allowed_tag_id_list": "tag",
    "IdentityGrant.permission.create.required_boundary_id_list": "boundary",
    "SSHGrant.filter.id": "identity",
    "SSHGrant.filter.tag_id_list": "tag",
    "SSHGrant.filter.boundary_id_list": "boundary",
}


def test_every_id_field_of_a_grant_is_read() -> None:
    found = {f"{cls.__name__}.{path}" for cls in _grant_classes() for path in _id_paths(cls)}
    assert found == set(_COVERED)


def test_walker_files_each_id_under_its_kind() -> None:
    grants: list[grant.Grant] = [
        grant.TagGrant(
            filter=grant.TagFilter(id=1), permission=grant.TagPermission(create=False, read=True, delete=False)
        ),
        grant.LiveGrant(filter=grant.LiveFilter(tag_id_list=[2]), permission=grant.LivePermission(read=True)),
        grant.IdentityGrant(
            filter=grant.TripletFilter(id=3, tag_id_list=[4], boundary_id_list=[5]),
            permission=grant.IdentityPermission(
                create=grant.IdentityCreatePermission(
                    allowed=True, allowed_tag_id_list=[6], required_boundary_id_list=[7]
                ),
                read=True,
                update=None,
                delete=False,
                add_tag_id_list=[8],
                del_tag_id_list=[9],
                invite_list=None,
            ),
        ),
    ]
    refs = grant.referenced_ids(grants)
    assert refs.tag == {1, 2, 4, 6, 8, 9}
    assert refs.identity == {3}
    assert refs.boundary == {5, 7}
    assert not refs.uses_self
