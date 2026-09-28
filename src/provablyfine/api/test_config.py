import os
import pathlib

import cryptography.fernet
import pytest

from . import config


def test_load_kek(tmp_path: pathlib.Path) -> None:
    kek_file = tmp_path / "kek.key"
    kek_file.write_bytes(os.urandom(32))
    conf = config.Config(kek_filename=str(kek_file))
    fernet = cryptography.fernet.Fernet(conf.load_kek())
    token = fernet.encrypt(b"hello")
    assert fernet.decrypt(token) == b"hello"


@pytest.mark.parametrize("length", [0, 16, 31, 33, 44])
def test_load_kek_rejects_wrong_length(tmp_path: pathlib.Path, length: int) -> None:
    kek_file = tmp_path / "kek.key"
    kek_file.write_bytes(os.urandom(length))
    conf = config.Config(kek_filename=str(kek_file))
    with pytest.raises(ValueError, match="32"):
        conf.load_kek()
