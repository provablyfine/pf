"""host-init for macOS.

sshd on macOS is started by launchd for each connection, so it reads its
configuration again every time and never needs a reload. macOS has no
`pam_exec`, so session deadlines are enforced by the session reaper.
"""

from __future__ import annotations

import os
import plistlib

import provablyfine_client as pfc

from . import base, common_steps, ops

STATE_DIR = "/var/db/pf"
LOG_DIR = "/var/log/pf"
ACCOUNT_KEY = f"{STATE_DIR}/account.key"
CONFIG = f"{STATE_DIR}/config.json"
ACCEPT_SCRATCH = f"{STATE_DIR}/accept.json"
# The principals command runs as an unprivileged user and writes here. The
# directory is not inside STATE_DIR: that one is closed to everyone but root,
# and a user cannot reach a directory below a directory it cannot enter.
DEADLINE_DIR = "/var/db/pf-deadlines"
# The bastion job runs as its own hidden account. It reads a private copy of
# the account key and the configuration from here, because STATE_DIR is closed.
BASTION_USER = "_pfbastion"
BASTION_DIR = "/var/db/pf-bastion"
BASTION_KEY = f"{BASTION_DIR}/account.key"
BASTION_CONFIG = f"{BASTION_DIR}/config.json"
LAUNCHD_DIR = "/Library/LaunchDaemons"
SSHD_LABEL = "com.openssh.sshd"
SSHD_PLIST = "/System/Library/LaunchDaemons/ssh.plist"
SSH_ACCESS_GROUP = "com.apple.access_ssh"
SSHD_CONFIG = "/etc/ssh/sshd_config"
CONFLICTING_DIRECTIVES = ("TrustedUserCAKeys", "AuthorizedPrincipalsCommand")
REFRESH_INTERVAL_SECONDS = 24 * 60 * 60

REFRESH_LABEL = "net.provablyfine.host-refresh"
BASTION_LABEL = "net.provablyfine.host-bastion"
REAPER_LABEL = "net.provablyfine.session-reaper"
LABELS = (REFRESH_LABEL, BASTION_LABEL, REAPER_LABEL)


def plist_path(label: str) -> str:
    return f"{LAUNCHD_DIR}/{label}.plist"


def _plist(
    label: str,
    argv: list[str],
    log_name: str,
    *,
    keep_alive: bool = False,
    start_interval: int | None = None,
    user: str | None = None,
    log_directory: str = LOG_DIR,
) -> bytes:
    definition: dict[str, object] = {
        "Label": label,
        "ProgramArguments": argv,
        "RunAtLoad": True,
        "StandardOutPath": f"{log_directory}/{log_name}.log",
        "StandardErrorPath": f"{log_directory}/{log_name}.log",
    }
    if user is not None:
        definition["UserName"] = user
    if keep_alive:
        definition["KeepAlive"] = True
    if start_interval is not None:
        definition["StartInterval"] = start_interval
    return plistlib.dumps(definition)


def _host_certificates(o: ops.Ops, host_keys_dir: str) -> list[str]:
    certificates = o.glob(f"{host_keys_dir}/ssh_host_*_key.cert")
    if certificates:
        return certificates
    # Host-refresh writes one certificate next to each host public key.
    return [path.removesuffix(".pub") + ".cert" for path in o.glob(f"{host_keys_dir}/ssh_host_*_key.pub")]


def _free_id(o: ops.Ops) -> int:
    """A user and group id in the range macOS keeps for service accounts that no account uses."""
    used: set[int] = set()
    for record, key in (("Users", "UniqueID"), ("Groups", "PrimaryGroupID")):
        for line in o.query(["dscl", ".", "-list", f"/{record}", key]).stdout.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].lstrip("-").isdigit():
                used.add(int(fields[1]))
    for candidate in range(300, 400):
        if candidate not in used:
            return candidate
    raise pfc.exceptions.UI("no free user id between 300 and 399 for the pf bastion account")


def _ensure_bastion_account(o: ops.Ops) -> None:
    """Create the hidden account the bastion job runs as: no login shell, no home directory."""
    if o.query(["dscl", ".", "-read", f"/Users/{BASTION_USER}"]).returncode == 0:
        return
    identifier = str(_free_id(o))
    group = f"/Groups/{BASTION_USER}"
    user = f"/Users/{BASTION_USER}"
    o.run(["dscl", ".", "-create", group])
    o.run(["dscl", ".", "-create", group, "PrimaryGroupID", identifier])
    o.run(["dscl", ".", "-create", user])
    for key, value in (
        ("UniqueID", identifier),
        ("PrimaryGroupID", identifier),
        ("UserShell", "/usr/bin/false"),
        ("NFSHomeDirectory", "/var/empty"),
        ("RealName", "provablyfine bastion"),
        ("IsHidden", "1"),
    ):
        o.run(["dscl", ".", "-create", user, key, value])


class Darwin:
    def __init__(self, installed_pf: str | None) -> None:
        # The pf that is running, when it comes from the installed package.
        self._installed_pf = installed_pf

    def _pf_binary(self, o: ops.Ops, settings: base.Settings) -> str:
        candidate = settings.pf_binary or self._installed_pf
        if candidate is None:
            raise pfc.exceptions.UI(
                "host-init on macOS needs the provablyfine installer package, which puts pf in /opt/provablyfine. "
                "A pf installed with pipx or Homebrew cannot be used. "
                "sshd only runs a command that only root can change."
            )
        if not o.is_executable(candidate):
            raise pfc.exceptions.UI(f"{candidate} is not an executable file")
        problem = o.path_problem(candidate)
        if problem is not None:
            raise pfc.exceptions.UI(
                f"sshd would refuse to run {candidate}: {problem}. "
                "Install the provablyfine installer package, which puts pf in /opt/provablyfine."
            )
        return candidate

    def init(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        for what, value in (
            ("--host-keys-dir", s.host_keys_dir),
            ("--ca-pub-path", s.ca_pub_path),
            ("--sshd-config-drop-in", s.sshd_config_drop_in),
            ("--auth-user", s.auth_user),
        ):
            common_steps.require_plain(value, what)
        pf_bin = self._pf_binary(o, s)
        drop_in_dir = os.path.dirname(s.sshd_config_drop_in)

        conflict = common_steps.conflicting_directive(
            o, [SSHD_CONFIG, *o.list_dir(drop_in_dir)], CONFLICTING_DIRECTIVES
        )
        if conflict is not None:
            raise pfc.exceptions.UI(f"conflicting sshd directive '{conflict}' found; remove before initializing pf")

        o.make_dir(STATE_DIR, 0o700)
        o.make_dir(LOG_DIR, 0o755)
        # The principals command runs as this user and writes the records.
        o.make_dir(DEADLINE_DIR, 0o700, owner=s.auth_user)
        key_pem = common_steps.new_account_key_pem()
        o.write_file(ACCOUNT_KEY, key_pem, 0o600, secret=True)
        o.write_file(
            CONFIG,
            common_steps.client_config(s.directory_url, ACCOUNT_KEY),
            0o600,
        )

        # The bastion job runs as its own account and reads its own copy of the key.
        _ensure_bastion_account(o)
        o.make_dir(BASTION_DIR, 0o700, owner=BASTION_USER)
        o.write_file(BASTION_KEY, key_pem, 0o600, secret=True, owner=BASTION_USER)
        o.write_file(
            BASTION_CONFIG,
            common_steps.client_config(s.directory_url, BASTION_KEY),
            0o600,
            owner=BASTION_USER,
        )

        # Accepting the invitation registers the account key with the server.
        # The configuration it writes is not used, so it goes to a scratch file.
        o.run([pf_bin, "-c", ACCEPT_SCRATCH, "accept", f"--invitation={s.invitation}", f"--key={ACCOUNT_KEY}"])
        o.remove(ACCEPT_SCRATCH)
        # pf keeps an empty lock file next to the configuration it writes.
        o.remove(f"{ACCEPT_SCRATCH}.lock")
        o.run(["ssh-keygen", "-A"])
        o.run(
            [
                pf_bin,
                "openssh",
                "host-refresh",
                f"--config={CONFIG}",
                f"--host-keys-dir={s.host_keys_dir}",
                f"--ca-pub-path={s.ca_pub_path}",
                "--no-sshd-reload",
            ]
        )

        o.make_dir(drop_in_dir, 0o755)
        o.write_file(
            s.sshd_config_drop_in,
            common_steps.sshd_drop_in(
                pf_bin,
                s,
                _host_certificates(o, s.host_keys_dir),
                principals_arguments=[f"--deadline-dir={DEADLINE_DIR}"],
            ),
            0o644,
        )

        services = {
            REFRESH_LABEL: _plist(
                REFRESH_LABEL,
                [
                    pf_bin,
                    "openssh",
                    "host-refresh",
                    f"--config={CONFIG}",
                    f"--host-keys-dir={s.host_keys_dir}",
                    f"--ca-pub-path={s.ca_pub_path}",
                ],
                "host-refresh",
                start_interval=REFRESH_INTERVAL_SECONDS,
            ),
            BASTION_LABEL: _plist(
                BASTION_LABEL,
                [pf_bin, "--config", BASTION_CONFIG, "bastion", "register", "--port", common_steps.ssh_port(o)],
                "host-bastion",
                keep_alive=True,
                user=BASTION_USER,
                # launchd opens the log as that user, and /var/log/pf belongs to root.
                log_directory=BASTION_DIR,
            ),
            REAPER_LABEL: _plist(
                REAPER_LABEL,
                [pf_bin, "openssh", "session-reaper", f"--deadline-dir={DEADLINE_DIR}"],
                "session-reaper",
                keep_alive=True,
            ),
        }
        for label, content in services.items():
            o.write_file(plist_path(label), content, 0o644)
        for label in services:
            o.run(["launchctl", "bootstrap", "system", plist_path(label)])

        if o.query(["launchctl", "print", f"system/{SSHD_LABEL}"]).returncode != 0:
            o.run(["launchctl", "enable", f"system/{SSHD_LABEL}"], check=False)
            o.run(["launchctl", "bootstrap", "system", SSHD_PLIST], check=False)
            o.note(
                "Remote Login was off, so pf tried to turn it on. "
                "Check it in System Settings, General, Sharing, Remote Login."
            )
        if o.query(["dseditgroup", "-o", "read", SSH_ACCESS_GROUP]).returncode == 0:
            o.note(
                f"SSH logins on this Mac are limited to members of the group {SSH_ACCESS_GROUP}. "
                f"Add a user with: sudo dseditgroup -o edit -a USER -t user {SSH_ACCESS_GROUP}"
            )

    def uninit(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        for label in LABELS:
            o.run(["launchctl", "bootout", f"system/{label}"], check=False)
            o.remove(plist_path(label))
        o.remove(s.sshd_config_drop_in)
        o.remove(s.ca_pub_path)
        for certificate in o.glob(f"{s.host_keys_dir}/ssh_host_*_key.cert"):
            o.remove(certificate)
        o.remove(STATE_DIR, recursive=True)
        o.remove(DEADLINE_DIR, recursive=True)
        o.remove(BASTION_DIR, recursive=True)
        o.run(["dscl", ".", "-delete", f"/Users/{BASTION_USER}"], check=False)
        o.run(["dscl", ".", "-delete", f"/Groups/{BASTION_USER}"], check=False)

    def reload_sshd(self, o: ops.Ops) -> None:
        """launchd starts a new sshd for every connection, which reads its configuration again."""
