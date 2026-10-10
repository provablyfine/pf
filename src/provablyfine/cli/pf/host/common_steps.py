"""Steps shared by the platform providers."""

from __future__ import annotations

import json
import os
import re
import stat
import typing

import provablyfine_client as pfc

from .... import jwk
from . import base, ops

# Values end up in sshd and service configuration files, where a space or a
# newline would start another setting.
_PLAIN = re.compile(r"[A-Za-z0-9_./@%+=,:-]+")


def require_plain(value: str, what: str) -> str:
    if _PLAIN.fullmatch(value) is None:
        raise pfc.exceptions.UI(
            f"{what} contains characters that cannot be written safely to a configuration file: {value!r}"
        )
    return value


def new_account_key_pem() -> bytes:
    return jwk.Private.generate_ed25519().to_pem()


def client_config(directory_url: str, account_key_file: str) -> str:
    """The pf configuration file of a host: where the directory is and which key signs requests."""
    return json.dumps({"directory_url": directory_url, "account_key_file": account_key_file}) + "\n"


def pf_install_problem(
    o: ops.Ops, path: str, prefixes: typing.Sequence[str], trusted_uid: int | None = None
) -> str | None:
    """Why `path` is not a correct system install of pf, or None when it is.

    sshd and the services run pf with the rights of other users, so only a trusted user may be able to change it.
    The resolved file must sit directly in one of `prefixes`.
    The file and every directory above it must belong to the trusted user and be closed to writes by group and others.
    Other users must be able to read and run the file and to search its directories.
    The root directory is not checked.
    `trusted_uid` is the owner of the root directory by default, which is root on a real system.

    A script whose interpreter lives in a user directory, such as a venv, passes: only pf itself is inspected.
    """
    trusted = o.stat("/").st_uid if trusted_uid is None else trusted_uid
    current = o.realpath(path)
    if os.path.dirname(current) not in {o.realpath(prefix) for prefix in prefixes}:
        return f"{current} is not in {' or '.join(prefixes)}"
    needed = stat.S_IROTH | stat.S_IXOTH
    while os.path.dirname(current) != current:
        try:
            info = o.stat(current)
        except OSError as e:
            return f"cannot inspect {current}: {e.strerror}"
        if info.st_uid != trusted:
            return f"{current} is owned by uid {info.st_uid}, not {trusted}"
        if info.st_mode & 0o022:
            return f"{current} can be written by its group or by others (mode {stat.S_IMODE(info.st_mode):o})"
        if info.st_mode & needed != needed:
            return f"{current} is closed to other users (mode {stat.S_IMODE(info.st_mode):o})"
        current = os.path.dirname(current)
        needed = stat.S_IXOTH
    return None


def conflicting_directive(o: ops.Ops, paths: typing.Iterable[str], names: typing.Iterable[str]) -> str | None:
    """The first directive in `names` that an existing sshd configuration file already sets."""
    pattern = re.compile(r"^(" + "|".join(re.escape(name) for name in names) + r")")
    for path in paths:
        text = o.read_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            found = pattern.match(line)
            if found is not None:
                return found.group(1)
    return None


def append_block(text: str, block: str) -> str:
    if text and not text.endswith("\n"):
        text += "\n"
    return text + block


def remove_block(text: str, begin: str, end: str) -> str:
    """Drop every line from a `begin` line to the next `end` line, both included."""
    kept: list[str] = []
    inside = False
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if not inside and stripped == begin:
            inside = True
            continue
        if inside:
            if stripped == end:
                inside = False
            continue
        kept.append(line)
    return "".join(kept)


def ssh_port(o: ops.Ops, config: str | None = None) -> str:
    """The port the local sshd listens on, 22 when it does not say."""
    command = ["sshd", "-T"] if config is None else ["sshd", "-T", "-f", config]
    for line in o.query(command).stdout.splitlines():
        if line.startswith("port "):
            return line.split()[1]
    return "22"


def sshd_drop_in(
    pf_bin: str,
    settings: base.Settings,
    certificates: typing.Sequence[str],
    principals_arguments: typing.Sequence[str] = (),
) -> str:
    """The sshd configuration that makes sshd trust the pf certificate authority."""
    command = [
        pf_bin,
        "openssh",
        "auth-principals",
        f"--host-certificate={settings.host_keys_dir}/ssh_host_ed25519_key.cert",
        "--username=%u",
        "--certificate=%k",
        *principals_arguments,
    ]
    lines = [f"TrustedUserCAKeys {settings.ca_pub_path}"]
    lines += [f"HostCertificate {path}" for path in certificates]
    lines += [
        f"AuthorizedPrincipalsCommand {' '.join(command)}",
        f"AuthorizedPrincipalsCommandUser {settings.auth_user}",
        "PubkeyAuthentication yes",
    ]
    return "\n".join(lines) + "\n"
