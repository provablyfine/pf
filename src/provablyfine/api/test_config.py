import os
import pathlib

import cryptography.fernet
import pytest

from .. import jwk
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


def test_user_extra_trusted_keys_default_to_none() -> None:
    assert config.Config().load_user_extra_trusted_keys() == []


def test_load_user_extra_trusted_keys_skips_comments_and_blank_lines(tmp_path: pathlib.Path) -> None:
    first = jwk.Private.generate(jwk.KeyType.ED25519).public().to_openssh()
    second = jwk.Private.generate(jwk.KeyType.ECDSA_NISTP256).public().to_openssh()
    keys_file = tmp_path / "extra.pub"
    keys_file.write_bytes(b"# old ca\n" + first + b" old-ca\n\n" + second + b"\n")
    conf = config.Config(user_extra_trusted_keys_filename=str(keys_file))
    assert conf.load_user_extra_trusted_keys() == [first, second]


@pytest.mark.parametrize("content", [b"", b"\n# only a comment\n", b"not a key\n"])
def test_load_user_extra_trusted_keys_rejects_a_file_without_valid_keys(tmp_path: pathlib.Path, content: bytes) -> None:
    keys_file = tmp_path / "extra.pub"
    keys_file.write_bytes(content)
    conf = config.Config(user_extra_trusted_keys_filename=str(keys_file))
    with pytest.raises(ValueError, match=r"extra\.pub"):
        conf.load_user_extra_trusted_keys()


def test_load_user_extra_trusted_keys_rejects_one_bad_line_among_good_ones(tmp_path: pathlib.Path) -> None:
    good = jwk.Private.generate(jwk.KeyType.ED25519).public().to_openssh()
    keys_file = tmp_path / "extra.pub"
    keys_file.write_bytes(good + b"\nssh-ed25519 AAAAgarbage\n")
    conf = config.Config(user_extra_trusted_keys_filename=str(keys_file))
    with pytest.raises(ValueError, match=":2:"):
        conf.load_user_extra_trusted_keys()


def test_load_user_extra_trusted_keys_rejects_a_missing_file(tmp_path: pathlib.Path) -> None:
    conf = config.Config(user_extra_trusted_keys_filename=str(tmp_path / "missing.pub"))
    with pytest.raises(FileNotFoundError):
        conf.load_user_extra_trusted_keys()
