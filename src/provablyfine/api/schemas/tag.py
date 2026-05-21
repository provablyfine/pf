from __future__ import annotations

import pydantic

from . import base


class TagNameValue(base.APIBase):
    model_config = pydantic.ConfigDict(frozen=True)
    name: str
    value: str


class Tag(base.APIBase):
    id: int
    name: str
    value: str


class TagListResponse(base.APIBase):
    tags: list[Tag]


class TagCreateRequest(base.APIBase):
    name: str
    value: str


class TagCreateResponse(base.APIBase):
    pass
