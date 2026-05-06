from __future__ import annotations

import pydantic


class APIBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(from_attributes=True, extra="forbid")
