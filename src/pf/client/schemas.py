import pydantic


class SshHostEntry(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    hostname: str
    type: str
    username_list: list[str] | None = None
    command_list: list[str] | None = None


class SshHostsResponse(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")

    hosts: list[SshHostEntry] = []
