import pydantic


class Tag(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    id: int
    name: str
    value: str


class TagsResponse(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    tags: list[Tag] = []


class SshHostEntry(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    hostname: str
    type: str
    username_list: list[str] | None = None
    command_list: list[str] | None = None


class SshHostsResponse(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    hosts: list[SshHostEntry] = []


class Tenant(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    id: int
    name: str
    display_name: str
    owner_id: int | None = None
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int


class TenantsResponse(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    tenants: list[Tenant] = []
