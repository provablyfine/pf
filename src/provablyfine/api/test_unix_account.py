import pytest

from . import config, unix_account


@pytest.mark.parametrize(
    "username,valid",
    [
        ("alice", True),
        ("_alice", True),
        ("al-ice_0", True),
        ("a" * 32, True),
        ("a" * 33, False),
        ("", False),
        ("Alice", False),
        ("0alice", False),
        ("-alice", False),
        ("al ice", False),
        ("alice$", False),
        ("alice\n", False),
    ],
)
def test_is_valid(username: str, valid: bool) -> None:
    assert unix_account.is_valid(username) == valid


def test_is_privileged_is_case_insensitive() -> None:
    # The configured list is written by a human: it must work whatever its case.
    assert unix_account.is_privileged("postgres", ["POSTGRES"])
    assert unix_account.is_privileged("postgres", ["postgres"])
    assert not unix_account.is_privileged("alice", ["postgres"])


def test_privileged_usernames_are_configurable() -> None:
    assert unix_account.is_privileged("root", config.Config().privileged_unix_usernames)
    assert not unix_account.is_privileged("alice", config.Config().privileged_unix_usernames)
    custom = config.Config.model_validate({"privileged_unix_usernames": ["alice"]})
    assert unix_account.is_privileged("alice", custom.privileged_unix_usernames)
    assert not unix_account.is_privileged("root", custom.privileged_unix_usernames)
