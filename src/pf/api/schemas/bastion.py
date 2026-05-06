from __future__ import annotations

import pydantic

from . import base, tag


class Bastion(base.APIBase):
    id: int
    url: str
    ssh_proxy_jump: str | None = None
    tag_list: list[tag.TagNameValue] = []


class BastionListResponse(base.APIBase):
    bastions: list[Bastion]


class BastionCreateRequest(base.APIBase):
    url: str
    ssh_proxy_jump: str | None = None
    tag_id_list: list[int] = []
    tag_name_value_list: list[tag.TagNameValue] = []

    @pydantic.model_validator(mode="after")
    def validate_tags(self):
        if len(self.tag_name_value_list) > 0 and len(self.tag_id_list) > 0:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        return self


class BastionUpdateRequest(base.APIBase):
    url: str | None = None
    ssh_proxy_jump: str | None = None
    tag_id_list: list[int] | None = None
    tag_name_value_list: list[tag.TagNameValue] | None = None

    @pydantic.model_validator(mode="after")
    def validate_tags(self):
        if self.tag_name_value_list is not None and self.tag_id_list is not None:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        if self.tag_name_value_list is not None or self.tag_id_list is not None:
            return self
        raise ValueError("At least one of 'tag_id_list', or 'tag_name_value_list' must be specified")
