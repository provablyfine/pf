import dataclasses
import json

from . import exceptions


@dataclasses.dataclass
class Config:
    directory_url: str
    root_key_id: str
    ignore_ssh_agent: bool
    account_key: str|None = None
    session_key: str|None = None

    @staticmethod
    def load(filename: str):
        try:
            with open(filename) as f:
                data = json.load(f)
                return Config(**data)
        except:
            raise exceptions.UI(f'Unable to load {filename}')

    def save(self, filename: str):
        with open(filename, 'w+') as f:
            json.dump(dataclasses.asdict(self), f)
