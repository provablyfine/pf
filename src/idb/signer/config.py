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
    key_duration_s: int = 3600


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


