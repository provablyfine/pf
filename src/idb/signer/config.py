from __future__ import annotations
import dataclasses
import json
import yaml
import os.path


@dataclasses.dataclass
class Config:
    debug: bool = False
    log_level: str = 'ERROR'
    base_url: str = 'http://127.0.0.1:8000'
    kek_filename: str = 'kek.key'
    host_key_duration_s: int = 24*3600
    host_keys_filename: str = 'keys.json'
    user_key_duration_s: int = 24*3600
    user_keys_filename: str = 'keys.json'


    @staticmethod
    def load(filename: str=None) -> Config:
        if filename is None:
            data = {}
        else:
            if not os.path.exists(filename):
                data = {}
            elif filename.endswith('.json'):
                with open(filename) as f:
                    data = json.load(f)
            elif filename.endswith('.yaml') or filename.endswith('.yml'):
                with open(filename) as f:
                    data = yaml.safe_load(f)
            else:
                assert False
        return Config(**data)


