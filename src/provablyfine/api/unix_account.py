from __future__ import annotations

import re

# Accounts that exist on most systems and already own something: either they come
# with passwordless sudo (the default user of every cloud image) or they own a
# service and its data. Mapping an identity to one of them would hand out that
# account's privileges to whoever holds a "{self}" grant, so we refuse to do it.
# This is only a default: it is overridden by the "privileged_unix_usernames"
# configuration option.
DEFAULT_PRIVILEGED_USERNAMES = [
    "root",
    # deployment accounts
    "deploy",
    "app",
    # cloud image users with passwordless sudo
    "ubuntu",
    "ec2-user",
    "centos",
    "debian",
    "admin",
    "azureuser",
    "rocky",
    "almalinux",
    # service accounts that own something
    "postgres",
    "mysql",
    "www-data",
    "nginx",
    "jenkins",
    "git",
    "nobody",
    "daemon",
    "bin",
    "sys",
]

# The conservative subset of what useradd(8) accepts, and what adduser(8) enforces
# by default: at most 32 characters, lowercase only, and neither a digit nor a dash
# to start with.
_VALID_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


def is_valid(username: str) -> bool:
    return _VALID_USERNAME.fullmatch(username) is not None


def is_privileged(username: str, privileged_usernames: list[str]) -> bool:
    # The comparison is case-insensitive: is_valid() already rejects uppercase input
    # but the configured list is written by a human and might not be lowercase.
    return username.lower() in [p.lower() for p in privileged_usernames]
