from __future__ import annotations

import typing

import pydantic

from . import base, bastion, jwk, tag


class IdentityBoundary(base.APIBase):
    id: int
    name: str


class IdentityRoleInfo(base.APIBase):
    id: int
    name: str


class Identity(base.APIBase):
    id: int
    name: str
    tags: list[tag.Tag]
    boundaries: list[IdentityBoundary]


class IdentitySelf(Identity):
    active_role: IdentityRoleInfo | None = None


class IdentityListResponse(base.APIBase):
    identities: list[Identity]


class IdentityCreateRequest(base.APIBase):
    name: str
    tag_id_list: list[int] = pydantic.Field(default_factory=list[int])
    tag_name_value_list: list[tag.TagNameValue] = pydantic.Field(default_factory=list[tag.TagNameValue])
    boundary_id_list: list[int] = pydantic.Field(default_factory=list[int])
    boundary_name_list: list[str] = pydantic.Field(default_factory=list[str])

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        if len(self.tag_name_value_list) > 0 and len(self.tag_id_list) > 0:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        if len(self.boundary_name_list) > 0 and len(self.boundary_id_list) > 0:
            raise ValueError("Cannot specify both 'boundary_id_list' and 'boundary_name_value_list'")
        return self


class IdentityCreateResponse(Identity):
    pass


class IdentityTagListOperation(base.APIBase):
    tag_id_list: list[int] = pydantic.Field(default_factory=list[int])
    tag_name_value_list: list[tag.TagNameValue] = pydantic.Field(default_factory=list[tag.TagNameValue])

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        if len(self.tag_name_value_list) > 0 and len(self.tag_id_list) > 0:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        return self


class IdentityTagAddOperation(IdentityTagListOperation):
    type: typing.Literal["add"] = "add"


class IdentityTagDelOperation(IdentityTagListOperation):
    type: typing.Literal["del"] = "del"


class IdentityTagSetOperation(IdentityTagListOperation):
    type: typing.Literal["set"] = "set"


IdentityTagOperation = typing.Annotated[
    IdentityTagAddOperation | IdentityTagDelOperation | IdentityTagSetOperation, pydantic.Field(discriminator="type")
]


class IdentityUpdateRequest(base.APIBase):
    name: str | None = None
    tags: list[IdentityTagOperation] | None = None

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self


class IdentityInviteRequest(base.APIBase):
    delivery: typing.Literal["manual", "email"]


class IdentityInviteManualResponse(base.APIBase):
    key: jwk.SymmetricJWK


class IdentitySelfTokenResponse(base.APIBase):
    token: str


class IdentitySelfBastionListResponse(base.APIBase):
    bastions: list[bastion.Bastion]
