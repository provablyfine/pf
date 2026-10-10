"""host-init for Windows, with the OpenSSH server that ships with Windows.

What the Windows sshd needs:

- It reads sshd_config once, when the service starts, and sends it to the
  processes that handle connections. A change needs a restart of the service.
  Sessions that are already open survive the restart.
- `Include` takes a path relative to %ProgramData%\\ssh. A path with a drive
  letter is read as relative as well, and silently matches nothing.
- The processes that handle connections run as a user with few rights. Every
  file that the configuration points to, the drop-in included, must be
  readable by the Users group. It must be writable only by administrators.
- A command that sshd runs must not be writable by anyone but administrators,
  and runs as the user named in AuthorizedPrincipalsCommandUser.
- There is no PAM, so the session reaper ends sessions at their deadline.
"""

from __future__ import annotations

import dataclasses
import json
import ntpath
import os
import re
import secrets
import subprocess
import typing
import xml.sax.saxutils

import provablyfine_client as pfc

from . import base, common_steps, ops

PROGRAM_DATA = os.environ.get("ProgramData", "C:\\ProgramData")
SSH_DIR = ntpath.join(PROGRAM_DATA, "ssh")
SSHD_CONFIG = ntpath.join(SSH_DIR, "sshd_config")
STATE_DIR = ntpath.join(PROGRAM_DATA, "pf")
LOG_DIR = ntpath.join(STATE_DIR, "logs")
ACCOUNT_KEY = ntpath.join(STATE_DIR, "account.key")
CONFIG = ntpath.join(STATE_DIR, "config.json")
ACCEPT_SCRATCH = ntpath.join(STATE_DIR, "accept.json")
AUTH_USER_MARKER = ntpath.join(STATE_DIR, "auth-user-created")
# The principals command writes here as an unprivileged user.
DEADLINE_DIR = ntpath.join(PROGRAM_DATA, "pf-deadlines")
# The bastion task runs as LOCAL SERVICE. It reads a private copy of the account
# key and the configuration from here, and writes its log here, because STATE_DIR
# is closed to everyone but administrators.
BASTION_DIR = ntpath.join(PROGRAM_DATA, "pf-bastion")
BASTION_KEY = ntpath.join(BASTION_DIR, "account.key")
BASTION_CONFIG = ntpath.join(BASTION_DIR, "config.json")

DEFAULTS = base.Defaults(
    host_keys_dir=SSH_DIR,
    ca_pub_path=ntpath.join(SSH_DIR, "pf_ca.pub"),
    sshd_config_drop_in=ntpath.join(SSH_DIR, "sshd_config.d", "10-pf.conf"),
    auth_user="pf-auth",
)

CONFLICTING_DIRECTIVES = ("TrustedUserCAKeys", "AuthorizedPrincipalsCommand")
BLOCK_BEGIN = "# BEGIN pf"
BLOCK_END = "# END pf"
BACKUP_SUFFIX = ".pf-backup"
TASK_FOLDER = "provablyfine"
TASKS = ("host-refresh", "host-bastion", "session-reaper")

# Well known security identifiers. They do not depend on the language of Windows.
_SYSTEM_SID = "S-1-5-18"
_LOCAL_SERVICE_SID = "S-1-5-19"
_SYSTEM = f"*{_SYSTEM_SID}"
_ADMINISTRATORS = "*S-1-5-32-544"
_USERS = "*S-1-5-32-545"
_LOCAL_SERVICE = f"*{_LOCAL_SERVICE_SID}"
_TRUSTED_SIDS = (
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    "S-1-3-0",
)

_PATH = re.compile(r"[A-Za-z]:[\\/][A-Za-z0-9_.\\/@%+=,~-]+")
_BINARY = re.compile(r"[A-Za-z]:[\\/][A-Za-z0-9_.\\/@%+=,~() -]+")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,20}")
_SERVICE = re.compile(r"[A-Za-z0-9_.-]{1,80}")

_POWERSHELL = ("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")


def is_elevated() -> bool:
    # The Win32 layer only loads on Windows. This module is imported everywhere.
    from .... import _w32 as w32

    return w32.security.is_user_an_admin()


def _require(value: str, pattern: re.Pattern[str], what: str) -> str:
    if pattern.fullmatch(value) is None:
        raise pfc.exceptions.UI(
            f"{what} contains characters that cannot be written safely to a configuration file: {value!r}"
        )
    return value


def slashes(path: str) -> str:
    """The form sshd_config uses."""
    return path.replace("\\", "/")


def sshd_value(path: str) -> str:
    """A path as sshd_config wants it, in quotes when it has a space."""
    text = slashes(path)
    return f'"{text}"' if " " in text else text


def include_target(drop_in: str, ssh_dir: str = SSH_DIR) -> str:
    """The path to give `Include`, which is relative to the ssh directory."""
    try:
        relative = ntpath.relpath(drop_in, ssh_dir)
    except ValueError as e:
        raise pfc.exceptions.UI(
            f"The drop-in {drop_in} must be on the same drive as {ssh_dir}: sshd only follows relative includes"
        ) from e
    return slashes(relative)


def add_include(text: str, include: str) -> str:
    """Put the managed block, with the include, before everything else.

    sshd takes the first value it finds, and a directive after a Match line
    only applies to that match. The top of the file is the only safe place.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    block = newline.join([BLOCK_BEGIN, f"Include {include}", BLOCK_END]) + newline
    return block + text


def remove_include(text: str) -> str:
    return common_steps.remove_block(text, BLOCK_BEGIN, BLOCK_END)


def account_script(name: str, password: str) -> str:
    """The PowerShell that creates the standard user the principals command runs as."""
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$password = ConvertTo-SecureString '{password}' -AsPlainText -Force\n"
        f"New-LocalUser -Name '{name}' -Password $password -PasswordNeverExpires -UserMayNotChangePassword"
        " -AccountNeverExpires -Description 'provablyfine sshd principals command' | Out-Null\n"
        f"Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member '{name}'\n"
        # New-LocalUser leaves the account without the "password required" flag.
        f"net.exe user '{name}' /passwordreq:yes | Out-Null\n"
        "if ($LASTEXITCODE -ne 0) { throw 'could not require a password for the new account' }\n"
    )


def new_password() -> str:
    # The suffix makes sure the password meets the usual complexity rules.
    return secrets.token_urlsafe(24) + "aA1!"


def task_xml(
    description: str,
    command: str,
    arguments: typing.Sequence[str],
    *,
    daily_at: str | None = None,
    repeat_minutes: int | None = None,
    restart_on_failure: bool = False,
    needs_network: bool = False,
    time_limit: str = "PT0S",
    unprivileged: bool = False,
) -> bytes:
    """A scheduled task in the format `schtasks /Create /XML` reads.

    It runs as SYSTEM, or as LOCAL SERVICE when `unprivileged`.

    It starts at boot. `repeat_minutes` makes the scheduler start it again when
    it is not running, which keeps a long running program alive.
    """
    triggers = ["<BootTrigger><Enabled>true</Enabled></BootTrigger>"]
    if daily_at is not None:
        triggers.append(
            "<CalendarTrigger>"
            f"<StartBoundary>2026-01-01T{daily_at}</StartBoundary><Enabled>true</Enabled>"
            "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"
            "</CalendarTrigger>"
        )
    if repeat_minutes is not None:
        triggers.append(
            "<TimeTrigger>"
            f"<Repetition><Interval>PT{repeat_minutes}M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
            "<StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>"
            "</TimeTrigger>"
        )
    restart = (
        "<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>" if restart_on_failure else ""
    )
    document = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        f"<RegistrationInfo><Description>{xml.sax.saxutils.escape(description)}</Description></RegistrationInfo>"
        f"<Triggers>{''.join(triggers)}</Triggers>"
        f'<Principals><Principal id="Author"><UserId>{_LOCAL_SERVICE_SID if unprivileged else _SYSTEM_SID}</UserId>'
        f"<RunLevel>{'LeastPrivilege' if unprivileged else 'HighestAvailable'}</RunLevel>"
        "</Principal></Principals>"
        "<Settings>"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>true</AllowHardTerminate>"
        "<StartWhenAvailable>true</StartWhenAvailable>"
        f"<RunOnlyIfNetworkAvailable>{'true' if needs_network else 'false'}</RunOnlyIfNetworkAvailable>"
        "<AllowStartOnDemand>true</AllowStartOnDemand>"
        "<Enabled>true</Enabled>"
        "<Hidden>false</Hidden>"
        f"<ExecutionTimeLimit>{time_limit}</ExecutionTimeLimit>"
        f"{restart}"
        "</Settings>"
        '<Actions Context="Author"><Exec>'
        f"<Command>{xml.sax.saxutils.escape(command)}</Command>"
        f"<Arguments>{xml.sax.saxutils.escape(subprocess.list2cmdline(list(arguments)))}</Arguments>"
        "</Exec></Actions>"
        "</Task>"
    )
    return document.encode("utf-16")


# Rights that let an account change what a file does, or replace it.
_FILE_WRITE = (
    "WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,"
    "ChangePermissions,TakeOwnership"
)
# For a directory above the file. Adding a subdirectory is harmless: the existing entries stay.
_DIRECTORY_WRITE = "WriteData,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership"


def _acl_script(path: str) -> str:
    quoted = path.replace("'", "''")
    trusted = ",".join(f"'{sid}'" for sid in _TRUSTED_SIDS)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$trusted = @({trusted})\n"
        f"$fileMask = [System.Security.AccessControl.FileSystemRights]'{_FILE_WRITE}'\n"
        f"$directoryMask = [System.Security.AccessControl.FileSystemRights]'{_DIRECTORY_WRITE}'\n"
        f"$leaf = '{quoted}'\n"
        "$p = $leaf\n"
        "$found = @()\n"
        "while ($p) {\n"
        "  $acl = Get-Acl -LiteralPath $p\n"
        "  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value\n"
        "  if ($trusted -notcontains $owner) { $found += @{ path = $p; kind = 'owner'; sid = $owner; rights = '' } }\n"
        "  $mask = if ($p -eq $leaf) { $fileMask } else { $directoryMask }\n"
        "  foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {\n"
        "    if ($ace.AccessControlType -ne 'Allow') { continue }\n"
        "    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly\n"
        "    if ($ace.PropagationFlags -band $inheritOnly) { continue }\n"
        "    if (($ace.FileSystemRights -band $mask) -and ($trusted -notcontains $ace.IdentityReference.Value)) {\n"
        "      $found += @{ path = $p; kind = 'write'; sid = $ace.IdentityReference.Value;"
        " rights = $ace.FileSystemRights.ToString() }\n"
        "    }\n"
        "  }\n"
        "  $p = Split-Path -Parent $p\n"
        "}\n"
        "ConvertTo-Json -Compress -InputObject @($found)\n"
    )


def parse_acl_problems(output: str) -> str | None:
    """Turn the output of `_acl_script` into a sentence, or None when the path is safe."""
    try:
        loaded: object = json.loads(output)
    except ValueError:
        return "its permissions could not be read"
    items = typing.cast("list[object]", loaded) if isinstance(loaded, list) else [loaded]
    if not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return "its permissions could not be read"
    fields = typing.cast("dict[str, object]", first)
    path, kind, sid, rights = fields.get("path"), fields.get("kind"), fields.get("sid"), fields.get("rights")
    if kind == "owner":
        return f"{path} is owned by {sid}, who could change who can write to it"
    return f"{path} can be written by {sid} ({rights})"


def install_problem(o: ops.Ops, path: str) -> str | None:
    """Why sshd would be unsafe to run `path` as a command, or None when it is fine."""
    result = o.query([*_POWERSHELL, "-Command", _acl_script(path)])
    if result.returncode != 0:
        return f"its permissions could not be read: {(result.stderr or result.stdout).strip()}"
    return parse_acl_problems(result.stdout)


def _icacls_closed(path: str, *extra: str) -> list[str]:
    """Allow SYSTEM and administrators everything and no one else, plus any `extra` grants."""
    return [
        "icacls",
        path,
        "/inheritance:r",
        "/grant:r",
        f"{_SYSTEM}:(OI)(CI)F",
        f"{_ADMINISTRATORS}:(OI)(CI)F",
        *extra,
    ]


def _icacls_readable(path: str) -> list[str]:
    """Let every user read a file, and only administrators change it."""
    return [
        "icacls",
        path,
        "/inheritance:r",
        "/grant:r",
        f"{_SYSTEM}:F",
        f"{_ADMINISTRATORS}:F",
        f"{_USERS}:R",
    ]


def _host_certificates(o: ops.Ops, host_keys_dir: str) -> list[str]:
    certificates = [ntpath.normpath(p) for p in o.glob(ntpath.join(host_keys_dir, "ssh_host_*_key.cert"))]
    if certificates:
        return certificates
    # Host-refresh writes one certificate next to each host public key.
    publics = o.glob(ntpath.join(host_keys_dir, "ssh_host_*_key.pub"))
    return [ntpath.normpath(p).removesuffix(".pub") + ".cert" for p in publics]


def _restart(o: ops.Ops, service: str) -> None:
    o.run(
        [
            *_POWERSHELL,
            "-Command",
            f"Set-Service -Name '{service}' -StartupType Automatic; Restart-Service -Name '{service}' -Force",
        ]
    )


class Windows:
    def __init__(self, installed_pf: str | None) -> None:
        # The pf that is running, when it comes from the installer.
        self._installed_pf = installed_pf

    def _pf_binary(self, o: ops.Ops, settings: base.Settings) -> str:
        candidate = settings.pf_binary or self._installed_pf
        if candidate is None:
            raise pfc.exceptions.UI(
                "host-init on Windows needs the pf that the installer puts in Program Files, "
                "installed for all users. A pf installed for one user, or with pipx, cannot be used: "
                "sshd only runs a command that only administrators can change."
            )
        candidate = ntpath.normpath(_require(candidate, _BINARY, "--pf-binary"))
        if not o.is_executable(candidate):
            raise pfc.exceptions.UI(f"{candidate} is not an executable file")
        problem = install_problem(o, candidate)
        if problem is not None:
            raise pfc.exceptions.UI(
                f"It is not safe to let sshd run {candidate}: {problem}. "
                "Install pf for all users, which puts it in Program Files."
            )
        return candidate

    def init(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        for what, value in (
            ("--host-keys-dir", s.host_keys_dir),
            ("--ca-pub-path", s.ca_pub_path),
            ("--sshd-config-drop-in", s.sshd_config_drop_in),
        ):
            _require(value, _PATH, what)
        _require(s.auth_user, _NAME, "--auth-user")
        _require(s.sshd_service, _SERVICE, "--sshd-service")
        main_config = _require(s.sshd_config or SSHD_CONFIG, _PATH, "--sshd-config")
        pf_bin = self._pf_binary(o, s)
        drop_in_dir = ntpath.dirname(s.sshd_config_drop_in)
        include = include_target(s.sshd_config_drop_in)

        original = o.read_text(main_config)
        if original is None:
            raise pfc.exceptions.UI(
                f"{main_config} does not exist. Install the OpenSSH Server optional feature of Windows first."
            )
        if o.query(["sc.exe", "query", s.sshd_service]).returncode != 0:
            raise pfc.exceptions.UI(f"There is no Windows service named {s.sshd_service}")
        if BLOCK_BEGIN in original.splitlines():
            raise pfc.exceptions.UI(f"pf block already present in {main_config}; remove before re-running host-init")
        conflict = common_steps.conflicting_directive(
            o, [main_config, *o.list_dir(drop_in_dir)], CONFLICTING_DIRECTIVES
        )
        if conflict is not None:
            raise pfc.exceptions.UI(f"conflicting sshd directive '{conflict}' found; remove before initializing pf")

        o.make_dir(STATE_DIR, 0o700)
        o.run(_icacls_closed(STATE_DIR))
        o.make_dir(LOG_DIR, 0o700)
        o.make_dir(DEADLINE_DIR, 0o700)
        if o.query(["net", "user", s.auth_user]).returncode != 0:
            o.run([*_POWERSHELL, "-Command", "-"], stdin=account_script(s.auth_user, new_password()).encode())
            o.write_file(AUTH_USER_MARKER, s.auth_user, None)
        # The principals command runs as this user and writes the records.
        o.run(_icacls_closed(DEADLINE_DIR, f"{s.auth_user}:(OI)(CI)M"))

        key_pem = common_steps.new_account_key_pem()
        o.write_file(ACCOUNT_KEY, key_pem, 0o600, secret=True)
        o.write_file(
            CONFIG,
            common_steps.client_config(s.directory_url, ACCOUNT_KEY),
            0o600,
        )
        o.make_dir(BASTION_DIR, 0o700)
        o.run(_icacls_closed(BASTION_DIR, f"{_LOCAL_SERVICE}:(OI)(CI)M"))
        o.write_file(BASTION_KEY, key_pem, 0o600, secret=True)
        o.write_file(
            BASTION_CONFIG,
            common_steps.client_config(s.directory_url, BASTION_KEY),
            0o600,
        )

        # Accepting the invitation registers the account key with the server.
        # The configuration it writes is not used, so it goes to a scratch file.
        o.run([pf_bin, "-c", ACCEPT_SCRATCH, "accept", f"--invitation={s.invitation}", f"--key={ACCOUNT_KEY}"])
        o.remove(ACCEPT_SCRATCH)
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

        certificates = _host_certificates(o, s.host_keys_dir)
        for path in [s.ca_pub_path, *certificates]:
            o.run(_icacls_readable(path))

        o.make_dir(drop_in_dir, 0o755)
        o.write_file(
            s.sshd_config_drop_in,
            common_steps.sshd_drop_in(
                sshd_value(pf_bin),
                dataclasses.replace(s, host_keys_dir=slashes(s.host_keys_dir), ca_pub_path=slashes(s.ca_pub_path)),
                [slashes(path) for path in certificates],
                principals_arguments=[f"--deadline-dir={slashes(DEADLINE_DIR)}"],
            ),
            0o644,
        )
        o.run(_icacls_readable(s.sshd_config_drop_in))

        self._enable_include(o, main_config, original, include, s.sshd_service)

        port = common_steps.ssh_port(o, main_config)
        log = ntpath.join(LOG_DIR, "{}.log")
        host_arguments = [
            f"--config={CONFIG}",
            f"--host-keys-dir={s.host_keys_dir}",
            f"--ca-pub-path={s.ca_pub_path}",
        ]
        tasks = {
            "host-refresh": task_xml(
                "Refresh the provablyfine SSH host certificates",
                pf_bin,
                [f"--log-filename={log.format('host-refresh')}", "openssh", "host-refresh", *host_arguments],
                daily_at="03:00:00",
                restart_on_failure=True,
                needs_network=True,
                time_limit="PT30M",
            ),
            "host-bastion": task_xml(
                "Register this host with the provablyfine bastion",
                pf_bin,
                [
                    f"--log-filename={ntpath.join(BASTION_DIR, 'host-bastion.log')}",
                    "--config",
                    BASTION_CONFIG,
                    "bastion",
                    "register",
                    "--port",
                    port,
                ],
                repeat_minutes=5,
                restart_on_failure=True,
                needs_network=True,
                unprivileged=True,
            ),
            "session-reaper": task_xml(
                "End SSH sessions when their provablyfine certificate deadline passes",
                pf_bin,
                [
                    f"--log-filename={log.format('session-reaper')}",
                    "openssh",
                    "session-reaper",
                    f"--deadline-dir={DEADLINE_DIR}",
                ],
                repeat_minutes=1,
                restart_on_failure=True,
            ),
        }
        for name, document in tasks.items():
            path = ntpath.join(STATE_DIR, f"{name}.xml")
            o.write_file(path, document, None)
            o.run(["schtasks", "/Create", "/TN", f"{TASK_FOLDER}\\{name}", "/XML", path, "/F"])
            o.remove(path)
        for name in tasks:
            o.run(["schtasks", "/Run", "/TN", f"{TASK_FOLDER}\\{name}"], check=False)

    def _enable_include(self, o: ops.Ops, main_config: str, original: str, include: str, service: str) -> None:
        """Add the include to sshd_config and restart sshd, or put the file back and say why."""
        backup = main_config + BACKUP_SUFFIX
        o.write_file(backup, original, None)
        o.write_file(main_config, add_include(original, include), None)
        checked = o.query(["sshd", "-t", "-f", main_config])
        if checked.returncode != 0:
            o.write_file(main_config, original, None)
            raise pfc.exceptions.UI(
                f"sshd refused the new configuration, so {main_config} was put back: "
                f"{(checked.stderr or checked.stdout).strip()}"
            )
        try:
            _restart(o, service)
        except pfc.exceptions.UI as e:
            o.write_file(main_config, original, None)
            o.run(_powershell_restart(service), check=False)
            raise pfc.exceptions.UI(f"sshd did not restart, so {main_config} was put back: {e}") from e

    def uninit(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        _require(s.sshd_service, _SERVICE, "--sshd-service")
        main_config = s.sshd_config or SSHD_CONFIG
        for name in TASKS:
            o.run(["schtasks", "/End", "/TN", f"{TASK_FOLDER}\\{name}"], check=False)
            o.run(["schtasks", "/Delete", "/TN", f"{TASK_FOLDER}\\{name}", "/F"], check=False)

        current = o.read_text(main_config)
        if current is not None and BLOCK_BEGIN in current.splitlines():
            o.write_file(main_config, remove_include(current), None)
            o.remove(main_config + BACKUP_SUFFIX)
            if o.query(["sshd", "-t", "-f", main_config]).returncode == 0:
                _restart(o, s.sshd_service)

        o.remove(s.sshd_config_drop_in)
        o.remove(s.ca_pub_path)
        for certificate in o.glob(ntpath.join(s.host_keys_dir, "ssh_host_*_key.cert")):
            o.remove(ntpath.normpath(certificate))

        created = (o.read_text(AUTH_USER_MARKER) or "").strip()
        if created and _NAME.fullmatch(created):
            o.run(["net", "user", created, "/delete"], check=False)
            o.run([*_POWERSHELL, "-Command", _profile_removal(created)], check=False)
        o.remove(STATE_DIR, recursive=True)
        o.remove(DEADLINE_DIR, recursive=True)
        o.remove(BASTION_DIR, recursive=True)

    def reload_sshd(self, o: ops.Ops) -> None:
        """sshd reads host certificates for every connection, so there is nothing to do."""


def _powershell_restart(service: str) -> list[str]:
    return [
        *_POWERSHELL,
        "-Command",
        f"Restart-Service -Name '{service}' -Force",
    ]


def _profile_removal(name: str) -> str:
    # Windows keeps the profile folder of a deleted user. Remove it when nothing holds it.
    return (
        "Get-CimInstance Win32_UserProfile | "
        f"Where-Object {{ $_.LocalPath -like '*\\{name}' }} | Remove-CimInstance -ErrorAction SilentlyContinue"
    )
