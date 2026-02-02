import dataclasses
import json

from . import exceptions


@dataclasses.dataclass
class Config:
    directory_url: str
    root_key_id: str
    ignore_ssh_agent: bool
    directory: dict = None
    account_key: str = None
    session_key: str = None

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
            json.dump(dict(
                directory_url=self.directory_url,
                root_key_id=self.root_key_id,
                ignore_ssh_agent=self.ignore_ssh_agent,
                directory=self.directory,
                account_key=self.account_key,
                session_key=self.session_key,
            ), f)
