from __future__ import annotations

import json
import ntpath
import os
import pathlib
import subprocess
import sys
import typing
import xml.etree.ElementTree

import provablyfine_client as pfc
import pytest

from . import base, ops, win32

INVITATION = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory?invitation=3qFA-_8Kx9mLp0o1"
DIRECTORY_URL = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory"
INJECTION_URL = "https://x.invalid/directory?invitation=k';touch /tmp/PWNED;#"
PF = "C:\\Program Files\\provablyfine\\pf.exe"
MAIN = "C:\\ProgramData\\ssh\\sshd_config"
ORIGINAL = (
    "Port 22\r\n"
    "#PubkeyAuthentication yes\r\n"
    "Subsystem\tsftp\tsftp-server.exe\r\n"
    "Match Group administrators\r\n"
    "  AuthorizedKeysFile x\r\n"
)
XMLNS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def _settings(**overrides: str | None) -> base.Settings:
    fields: dict[str, str | None] = {
        "invitation": INVITATION,
        "directory_url": DIRECTORY_URL,
        "host_keys_dir": "C:\\ProgramData\\ssh",
        "ca_pub_path": "C:\\ProgramData\\ssh\\pf_ca.pub",
        "sshd_config_drop_in": "C:\\ProgramData\\ssh\\sshd_config.d\\10-pf.conf",
        "auth_user": "pf-auth",
        "pf_binary": None,
        "sshd_config": None,
        "sshd_service": "sshd",
    }
    fields.update(overrides)
    return base.Settings(**typing.cast("dict[str, typing.Any]", fields))


def _queries(
    *,
    user_exists: bool = False,
    service_exists: bool = True,
    acl: str = "[]",
    sshd_test: ops.QueryResult | None = None,
    port: str = "22",
) -> typing.Callable[[typing.Sequence[str]], ops.QueryResult]:
    def query(argv: typing.Sequence[str]) -> ops.QueryResult:
        match list(argv):
            case ["sc.exe", "query", _]:
                return ops.QueryResult(0 if service_exists else 1060, "")
            case ["net", "user", _]:
                return ops.QueryResult(0 if user_exists else 2, "")
            case ["powershell", *_, "-Command", script] if "Get-Acl" in script:
                return ops.QueryResult(0, acl)
            case ["sshd", "-t", "-f", _]:
                return sshd_test or ops.QueryResult(0, "")
            case ["sshd", "-T", "-f", _]:
                return ops.QueryResult(0, f"port {port}\n")
        return ops.QueryResult(127, "")

    return query


def _host(tmp_path: pathlib.Path, *, config: str = ORIGINAL, certificates: bool = True) -> None:
    _skip_without_posix_paths()
    pf = tmp_path / "drive_c" / "Program Files" / "provablyfine" / "pf.exe"
    pf.parent.mkdir(parents=True)
    pf.write_text("exe")
    pf.chmod(0o755)
    ssh = tmp_path / "drive_c" / "ProgramData" / "ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    (ssh / "sshd_config").write_bytes(config.encode())
    if certificates:
        for key_type in ("ed25519", "ecdsa", "rsa"):
            (ssh / f"ssh_host_{key_type}_key.cert").write_text("cert")


class _RestartFails(ops.DryRunOps):
    def run(self, argv: typing.Sequence[str], *, check: bool = True, stdin: bytes | None = None) -> None:
        if check and "Restart-Service" in argv[-1] and "Set-Service" in argv[-1]:
            raise pfc.exceptions.UI("command failed with exit code 1: Restart-Service")
        super().run(argv, check=check, stdin=stdin)


def _skip_without_posix_paths() -> None:
    # The tests lay out a Windows host under a temporary directory, which only works with POSIX paths.
    if sys.platform == "win32":
        pytest.skip("the temporary tree stands in for C:, which needs POSIX paths")


def _dry(tmp_path: pathlib.Path, **query_options: typing.Any) -> ops.DryRunOps:
    return ops.DryRunOps(root=tmp_path, query=_queries(**query_options))


def _init(tmp_path: pathlib.Path, settings: base.Settings | None = None, **query_options: typing.Any) -> ops.DryRunOps:
    dry = _dry(tmp_path, **query_options)
    win32.Windows(PF).init(dry, settings or _settings())
    return dry


def _runs(dry: ops.DryRunOps) -> list[tuple[str, ...]]:
    return [a.argv for a in dry.actions if isinstance(a, ops.Run)]


def _writes(dry: ops.DryRunOps, path: str) -> list[ops.WriteFile]:
    return [a for a in dry.actions if isinstance(a, ops.WriteFile) and a.path == path]


def _only_write(dry: ops.DryRunOps, path: str) -> ops.WriteFile:
    found = _writes(dry, path)
    assert len(found) == 1, f"{path} written {len(found)} times"
    return found[0]


def _text(write: ops.WriteFile) -> str:
    return write.content.decode()


def test_init_runs_the_steps_in_order(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    runs = _runs(dry)
    kinds = [argv[0] if argv[0] != "powershell" else f"powershell:{argv[-1][:12]}" for argv in runs]
    assert kinds == [
        "icacls",  # the state directory is closed before anything goes into it
        "powershell:-",  # the principals user is created
        "icacls",  # the deadline directory is opened to that user
        "icacls",  # the kill request directory is opened to LOCAL SERVICE
        "icacls",  # the live events directory is opened to LOCAL SERVICE
        "icacls",  # the bastion directory is opened to LOCAL SERVICE
        PF,  # accept
        "ssh-keygen",
        PF,  # host-refresh
        "icacls",  # the CA key can be read by everyone
        "icacls",
        "icacls",
        "icacls",  # the host certificates
        "icacls",  # the drop-in
        "powershell:Set-Service ",  # sshd restarts
        "schtasks",
        "schtasks",
        "schtasks",
        "schtasks",
        "schtasks",
        "schtasks",
    ]
    accept = runs[6]
    assert accept[1:3] == ("-c", "C:\\ProgramData\\pf\\accept.json")
    assert f"--invitation={INVITATION}" in accept
    assert "--key=C:\\ProgramData\\pf\\account.key" in accept


def test_init_closes_the_state_directory_to_everyone_but_administrators(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path))
    assert runs[0] == (
        "icacls",
        "C:\\ProgramData\\pf",
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
    )


def test_init_opens_the_deadline_directory_to_the_principals_user_only(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path))
    assert runs[2] == (
        "icacls",
        "C:\\ProgramData\\pf-deadlines",
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "pf-auth:(OI)(CI)M",
    )
    assert not os.path.commonpath(["C:/ProgramData/pf-deadlines", "C:/ProgramData/pf"]) == "C:/ProgramData/pf"


def test_init_limits_the_live_events_directory_to_administrators_and_the_bastion_task(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path))
    assert runs[4] == (
        "icacls",
        "C:\\ProgramData\\pf-live-events",
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-19:(OI)(CI)M",
    )


def test_init_limits_the_kill_request_directory_to_administrators_and_the_bastion_task(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path))
    assert runs[3] == (
        "icacls",
        "C:\\ProgramData\\pf-kill-requests",
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-19:(OI)(CI)M",
    )


def test_init_creates_the_principals_user_with_a_password_nobody_sees(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    create = next(a for a in dry.actions if isinstance(a, ops.Run) and a.argv[-1] == "-")
    assert create.stdin is not None
    script = create.stdin.decode()
    assert "New-LocalUser -Name 'pf-auth'" in script
    assert "-PasswordNeverExpires -UserMayNotChangePassword" in script
    assert "Get-LocalGroup -SID 'S-1-5-32-545'" in script
    assert "net.exe user 'pf-auth' /passwordreq:yes" in script
    password = script.split("ConvertTo-SecureString '")[1].split("'")[0]
    assert len(password) > 30
    assert password not in dry.describe()
    assert all(password not in arg for argv in _runs(dry) for arg in argv)
    assert _only_write(dry, "C:\\ProgramData\\pf\\auth-user-created").content == b"pf-auth"


def test_init_does_not_create_a_user_that_exists_and_does_not_claim_it(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, user_exists=True)
    assert not [a for a in dry.actions if isinstance(a, ops.Run) and a.argv[-1] == "-"]
    assert not _writes(dry, "C:\\ProgramData\\pf\\auth-user-created")


def test_each_user_gets_a_new_password() -> None:
    first, second = win32.new_password(), win32.new_password()
    assert first != second
    assert "'" not in first
    assert first.endswith("aA1!")


def test_init_stores_a_fresh_account_key_and_the_client_config(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    key = _only_write(dry, "C:\\ProgramData\\pf\\account.key")
    assert key.secret
    assert key.content.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert "PRIVATE KEY" not in dry.describe()
    config = json.loads(_text(_only_write(dry, "C:\\ProgramData\\pf\\config.json")))
    assert config == {"directory_url": DIRECTORY_URL, "account_key_file": "C:\\ProgramData\\pf\\account.key"}


def test_init_removes_the_scratch_config_that_accept_writes(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    removed = [a.path for a in _init(tmp_path).actions if isinstance(a, ops.Remove)]
    assert "C:\\ProgramData\\pf\\accept.json" in removed
    assert "C:\\ProgramData\\pf\\accept.json.lock" in removed


def test_init_lets_everyone_read_the_files_sshd_needs_and_only_administrators_change_them(
    tmp_path: pathlib.Path,
) -> None:
    _host(tmp_path)
    readable = [argv for argv in _runs(_init(tmp_path)) if argv[0] == "icacls" and argv[-1] == "*S-1-5-32-545:R"]
    assert [argv[1] for argv in readable] == [
        "C:\\ProgramData\\ssh\\pf_ca.pub",
        "C:\\ProgramData\\ssh\\ssh_host_ecdsa_key.cert",
        "C:\\ProgramData\\ssh\\ssh_host_ed25519_key.cert",
        "C:\\ProgramData\\ssh\\ssh_host_rsa_key.cert",
        "C:\\ProgramData\\ssh\\sshd_config.d\\10-pf.conf",
    ]
    assert readable[0][2:] == ("/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-32-545:R")


def test_init_writes_the_drop_in_with_slashes_and_a_quoted_command(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    drop_in = _only_write(_init(tmp_path), "C:\\ProgramData\\ssh\\sshd_config.d\\10-pf.conf")
    assert _text(drop_in) == (
        "TrustedUserCAKeys C:/ProgramData/ssh/pf_ca.pub\n"
        "HostCertificate C:/ProgramData/ssh/ssh_host_ecdsa_key.cert\n"
        "HostCertificate C:/ProgramData/ssh/ssh_host_ed25519_key.cert\n"
        "HostCertificate C:/ProgramData/ssh/ssh_host_rsa_key.cert\n"
        'AuthorizedPrincipalsCommand "C:/Program Files/provablyfine/pf.exe" openssh auth-principals'
        " --host-certificate=C:/ProgramData/ssh/ssh_host_ed25519_key.cert --username=%u --certificate=%k"
        " --deadline-dir=C:/ProgramData/pf-deadlines\n"
        "AuthorizedPrincipalsCommandUser pf-auth\n"
        "PubkeyAuthentication yes\n"
    )


def test_init_puts_the_include_before_everything_and_keeps_the_original_line_endings(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    edits = _writes(dry, MAIN)
    assert [_text(w) for w in edits] == [
        "# BEGIN pf\r\nInclude sshd_config.d/10-pf.conf\r\n# END pf\r\n" + ORIGINAL,
    ]
    assert edits[0].mode is None
    assert _text(_only_write(dry, MAIN + ".pf-backup")) == ORIGINAL


def test_init_checks_the_new_configuration_before_it_restarts_sshd(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    restarts = [argv for argv in _runs(_init(tmp_path)) if "Restart-Service" in argv[-1]]
    assert restarts == [
        (
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Set-Service -Name 'sshd' -StartupType Automatic; Restart-Service -Name 'sshd' -Force",
        )
    ]


def test_init_puts_the_configuration_back_when_sshd_refuses_it(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _dry(
        tmp_path, sshd_test=ops.QueryResult(255, "", "C:/ProgramData/ssh/sshd_config line 1: Bad configuration option")
    )
    with pytest.raises(pfc.exceptions.UI, match=r"put back: .*Bad configuration option"):
        win32.Windows(PF).init(dry, _settings())
    assert _text(_writes(dry, MAIN)[-1]) == ORIGINAL
    assert not [argv for argv in _runs(dry) if argv[0] == "schtasks" or "Restart-Service" in argv[-1]]


def test_init_puts_the_configuration_back_when_sshd_does_not_restart(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _RestartFails(root=tmp_path, query=_queries())
    with pytest.raises(pfc.exceptions.UI, match=r"did not restart, so .* was put back"):
        win32.Windows(PF).init(dry, _settings())
    assert _text(_writes(dry, MAIN)[-1]) == ORIGINAL
    assert any("Restart-Service -Name 'sshd' -Force" == argv[-1] for argv in _runs(dry))
    assert not [argv for argv in _runs(dry) if argv[0] == "schtasks"]


def test_init_can_edit_another_config_and_restart_another_service(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    spike = tmp_path / "drive_c" / "spike"
    spike.mkdir()
    (spike / "sshd_config").write_text("Port 2222\n")
    dry = _init(
        tmp_path,
        _settings(sshd_config="C:\\spike\\sshd_config", sshd_service="pfspike"),
        port="2222",
    )
    assert _text(_writes(dry, "C:\\spike\\sshd_config")[0]).endswith("# END pf\nPort 2222\n")
    assert not _writes(dry, MAIN)
    assert any("Restart-Service -Name 'pfspike'" in argv[-1] for argv in _runs(dry))
    bastion = xml.etree.ElementTree.fromstring(  # noqa: S314
        _xml(_only_write(dry, "C:\\ProgramData\\pf\\host-bastion.xml"))
    )
    assert "2222" in bastion.findtext("t:Actions/t:Exec/t:Arguments", namespaces=XMLNS, default="")


def _xml(write: ops.WriteFile) -> str:
    return write.content.decode("utf-16")


def _task(dry: ops.DryRunOps, name: str) -> xml.etree.ElementTree.Element:
    return xml.etree.ElementTree.fromstring(  # noqa: S314
        _xml(_only_write(dry, f"C:\\ProgramData\\pf\\{name}.xml"))
    )


def test_init_registers_a_task_for_each_service_and_starts_it(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    schtasks = [argv for argv in _runs(dry) if argv[0] == "schtasks"]
    assert schtasks[:3] == [
        ("schtasks", "/Create", "/TN", f"provablyfine\\{name}", "/XML", f"C:\\ProgramData\\pf\\{name}.xml", "/F")
        for name in win32.TASKS
    ]
    assert schtasks[3:] == [("schtasks", "/Run", "/TN", f"provablyfine\\{name}") for name in win32.TASKS]
    removed = [a.path for a in dry.actions if isinstance(a, ops.Remove)]
    assert all(f"C:\\ProgramData\\pf\\{name}.xml" in removed for name in win32.TASKS)


def test_the_tasks_run_the_installed_pf_and_only_the_bastion_is_unprivileged(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    for name in win32.TASKS:
        task = _task(dry, name)
        expected = "S-1-5-19" if name == "host-bastion" else "S-1-5-18"
        assert task.findtext("t:Principals/t:Principal/t:UserId", namespaces=XMLNS) == expected
        assert task.findtext("t:Actions/t:Exec/t:Command", namespaces=XMLNS) == PF
        assert task.find("t:Triggers/t:BootTrigger", XMLNS) is not None
        assert task.findtext("t:Settings/t:AllowHardTerminate", namespaces=XMLNS) == "true"
        assert task.findtext("t:Settings/t:MultipleInstancesPolicy", namespaces=XMLNS) == "IgnoreNew"
        assert _xml(_only_write(dry, f"C:\\ProgramData\\pf\\{name}.xml")).startswith(
            '<?xml version="1.0" encoding="UTF-16"?>'
        )


def test_the_reaper_task_is_started_again_every_minute_when_it_is_not_running(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    task = _task(_init(tmp_path), "session-reaper")
    assert task.findtext("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval", namespaces=XMLNS) == "PT1M"
    assert task.findtext("t:Triggers/t:TimeTrigger/t:Repetition/t:StopAtDurationEnd", namespaces=XMLNS) == "false"
    assert task.findtext("t:Settings/t:RestartOnFailure/t:Interval", namespaces=XMLNS) == "PT1M"
    assert task.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=XMLNS) == "PT0S"
    arguments = task.findtext("t:Actions/t:Exec/t:Arguments", namespaces=XMLNS, default="")
    assert arguments == subprocess.list2cmdline(
        [
            "--log-filename=C:\\ProgramData\\pf\\logs\\session-reaper.log",
            "openssh",
            "session-reaper",
            "--deadline-dir=C:\\ProgramData\\pf-deadlines",
            "--kill-dir=C:\\ProgramData\\pf-kill-requests",
            "--live-dir=C:\\ProgramData\\pf-live-events",
        ]
    )


def test_the_bastion_task_registers_the_port_sshd_listens_on(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    task = _task(_init(tmp_path, port="2200"), "host-bastion")
    arguments = task.findtext("t:Actions/t:Exec/t:Arguments", namespaces=XMLNS, default="")
    assert arguments.endswith(
        "--config C:\\ProgramData\\pf-bastion\\config.json bastion register --port 2200"
        " --live-events-dir=C:\\ProgramData\\pf-live-events"
        " --kill-dir=C:\\ProgramData\\pf-kill-requests"
    )
    assert task.findtext("t:Principals/t:Principal/t:UserId", namespaces=XMLNS) == "S-1-5-19"
    assert task.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=XMLNS) == "LeastPrivilege"
    assert task.findtext("t:Principals/t:Principal/t:LogonType", namespaces=XMLNS) == "ServiceAccount"
    assert task.findtext("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval", namespaces=XMLNS) == "PT5M"
    assert task.findtext("t:Settings/t:RunOnlyIfNetworkAvailable", namespaces=XMLNS) == "true"


def test_the_refresh_task_runs_every_day_and_at_boot(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    task = _task(_init(tmp_path), "host-refresh")
    assert task.findtext("t:Triggers/t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval", namespaces=XMLNS) == "1"
    assert task.findtext("t:Settings/t:StartWhenAvailable", namespaces=XMLNS) == "true"
    arguments = task.findtext("t:Actions/t:Exec/t:Arguments", namespaces=XMLNS, default="")
    assert "openssh host-refresh --config=C:\\ProgramData\\pf\\config.json" in arguments
    assert "--no-sshd-reload" not in arguments


def test_task_xml_escapes_what_it_is_given() -> None:
    document = win32.task_xml("a <b> & c", "C:\\x & y\\pf.exe", ["--flag=<1>", "two words"])
    root = xml.etree.ElementTree.fromstring(  # noqa: S314
        document.decode("utf-16")
    )
    assert root.findtext("t:RegistrationInfo/t:Description", namespaces=XMLNS) == "a <b> & c"
    assert root.findtext("t:Actions/t:Exec/t:Command", namespaces=XMLNS) == "C:\\x & y\\pf.exe"
    assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=XMLNS) == '--flag=<1> "two words"'


def test_init_refuses_when_pf_is_not_installed_for_all_users(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="installed for all users"):
        win32.Windows(None).init(dry, _settings())
    assert dry.actions == []


def test_init_refuses_a_pf_that_users_can_change(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    problem = json.dumps([{"path": PF, "kind": "write", "sid": "S-1-5-32-545", "rights": "Modify, Synchronize"}])
    dry = _dry(tmp_path, acl=problem)
    with pytest.raises(
        pfc.exceptions.UI, match=r"not safe to let sshd run .*pf\.exe: .* can be written by S-1-5-32-545"
    ):
        win32.Windows(PF).init(dry, _settings())
    assert dry.actions == []


def test_init_refuses_a_pf_whose_permissions_cannot_be_read(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=lambda argv: ops.QueryResult(1, "", "Access is denied"))
    with pytest.raises(pfc.exceptions.UI, match="permissions could not be read: Access is denied"):
        win32.Windows(PF).init(dry, _settings())


def test_init_refuses_a_pf_that_does_not_exist(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="not an executable file"):
        win32.Windows(PF).init(_dry(tmp_path), _settings(pf_binary="C:\\Program Files\\provablyfine\\missing.exe"))


def test_acl_problems_are_described() -> None:
    assert win32.parse_acl_problems("[]") is None
    assert win32.parse_acl_problems("") == "its permissions could not be read"
    assert win32.parse_acl_problems("[1]") == "its permissions could not be read"
    owner = json.dumps([{"path": "C:\\x", "kind": "owner", "sid": "S-1-5-21-1-2-3-1001", "rights": ""}])
    assert (
        win32.parse_acl_problems(owner) == "C:\\x is owned by S-1-5-21-1-2-3-1001, who could change who can write to it"
    )
    single = json.dumps({"path": "C:\\y", "kind": "write", "sid": "S-1-1-0", "rights": "Write"})
    assert win32.parse_acl_problems(single) == "C:\\y can be written by S-1-1-0 (Write)"


def test_the_permission_script_looks_at_every_directory_above_the_file_and_knows_the_trusted_accounts() -> None:
    script = win32._acl_script("C:\\Program Files\\o'brien\\pf.exe")
    assert "'C:\\Program Files\\o''brien\\pf.exe'" in script
    for sid in ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"):
        assert f"'{sid}'" in script
    assert "Split-Path -Parent" in script
    assert "InheritOnly" in script


@pytest.mark.parametrize("directive", ["TrustedUserCAKeys C:/other.pub", "AuthorizedPrincipalsCommand C:/x.exe"])
def test_init_changes_nothing_when_the_main_configuration_has_a_conflict(
    tmp_path: pathlib.Path, directive: str
) -> None:
    _host(tmp_path, config=ORIGINAL + directive + "\r\n")
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="conflicting sshd directive"):
        win32.Windows(PF).init(dry, _settings())
    assert dry.actions == []


def test_init_sees_a_conflict_in_the_drop_in_directory(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "drive_c" / "ProgramData" / "ssh" / "sshd_config.d" / "50-other.conf").write_text(
        "TrustedUserCAKeys C:/x\n"
    )
    with pytest.raises(pfc.exceptions.UI, match="conflicting sshd directive"):
        win32.Windows(PF).init(_dry(tmp_path), _settings())


def test_init_refuses_to_run_twice(tmp_path: pathlib.Path) -> None:
    _host(tmp_path, config="# BEGIN pf\r\nInclude sshd_config.d/10-pf.conf\r\n# END pf\r\n" + ORIGINAL)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="pf block already present"):
        win32.Windows(PF).init(dry, _settings())
    assert dry.actions == []


def test_init_asks_for_the_openssh_server_when_it_is_missing(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "drive_c" / "ProgramData" / "ssh" / "sshd_config").unlink()
    with pytest.raises(pfc.exceptions.UI, match="OpenSSH Server optional feature"):
        win32.Windows(PF).init(_dry(tmp_path), _settings())


def test_init_refuses_an_unknown_service(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _dry(tmp_path, service_exists=False)
    with pytest.raises(pfc.exceptions.UI, match="no Windows service named sshd"):
        win32.Windows(PF).init(dry, _settings())
    assert dry.actions == []


@pytest.mark.parametrize("field", ["host_keys_dir", "ca_pub_path", "sshd_config_drop_in", "sshd_config"])
@pytest.mark.parametrize(
    "value",
    [
        "C:\\ProgramData\\ssh\nPermitRootLogin yes",
        "C:\\Program Data\\ssh",
        "C:\\ssh'x",
        'C:\\ssh"x',
        "relative\\path",
        "C:\\$env",
    ],
)
def test_init_refuses_paths_that_cannot_be_written_safely(tmp_path: pathlib.Path, field: str, value: str) -> None:
    _host(tmp_path)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        win32.Windows(PF).init(dry, _settings(**{field: value}))
    assert dry.actions == []


@pytest.mark.parametrize("name", ["", "has space", "x" * 21, "a'b", "a\nb", "a;b"])
def test_init_refuses_unsafe_user_names(tmp_path: pathlib.Path, name: str) -> None:
    _host(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        win32.Windows(PF).init(_dry(tmp_path), _settings(auth_user=name))


@pytest.mark.parametrize("service", ["", "a b", "a'b", "a;b"])
def test_init_refuses_unsafe_service_names(tmp_path: pathlib.Path, service: str) -> None:
    _host(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        win32.Windows(PF).init(_dry(tmp_path), _settings(sshd_service=service))


def test_init_keeps_an_invitation_with_shell_syntax_as_one_argument(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, _settings(invitation=INJECTION_URL))
    accept = next(argv for argv in _runs(dry) if "accept" in argv)
    assert f"--invitation={INJECTION_URL}" in accept
    for argv in _runs(dry):
        assert argv[0].lower() not in ("cmd", "cmd.exe", "sh", "bash")
    written = "".join(a.content.decode(errors="replace") for a in dry.actions if isinstance(a, ops.WriteFile))
    assert "PWNED" not in written.replace("\x00", "")


def test_include_target_is_relative_to_the_ssh_directory() -> None:
    assert win32.include_target("C:\\ProgramData\\ssh\\sshd_config.d\\10-pf.conf") == "sshd_config.d/10-pf.conf"
    assert win32.include_target("C:\\ProgramData\\ssh\\10-pf.conf") == "10-pf.conf"
    assert win32.include_target("C:\\spike\\dropin.conf") == "../../spike/dropin.conf"
    with pytest.raises(pfc.exceptions.UI, match="same drive"):
        win32.include_target("D:\\conf\\10-pf.conf")


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_the_include_block_goes_in_and_out_without_touching_the_rest(newline: str) -> None:
    original = newline.join(["Port 22", "Match User x", "  Banner none", ""])
    added = win32.add_include(original, "sshd_config.d/10-pf.conf")
    assert added.startswith(f"# BEGIN pf{newline}Include sshd_config.d/10-pf.conf{newline}# END pf{newline}Port 22")
    assert win32.remove_include(added) == original


def test_the_include_block_is_added_to_an_empty_file() -> None:
    assert win32.add_include("", "x.conf") == "# BEGIN pf\nInclude x.conf\n# END pf\n"


def test_paths_for_sshd_use_forward_slashes_and_quote_spaces() -> None:
    assert win32.slashes("C:\\a\\b") == "C:/a/b"
    assert win32.sshd_value("C:\\ProgramData\\ssh") == "C:/ProgramData/ssh"
    assert win32.sshd_value("C:\\Program Files\\pf\\pf.exe") == '"C:/Program Files/pf/pf.exe"'


def _created_host(tmp_path: pathlib.Path, *, config: str | None = None, marker: str | None = "pf-auth") -> None:
    include = "# BEGIN pf\r\nInclude sshd_config.d/10-pf.conf\r\n# END pf\r\n"
    _host(tmp_path, config=config if config is not None else include + ORIGINAL)
    state = tmp_path / "drive_c" / "ProgramData" / "pf"
    state.mkdir(parents=True)
    if marker is not None:
        (state / "auth-user-created").write_text(marker)


def test_uninit_undoes_the_install(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path)
    dry = _dry(tmp_path)
    win32.Windows(PF).uninit(dry, _settings())
    runs = _runs(dry)
    for name in win32.TASKS:
        assert ("schtasks", "/End", "/TN", f"provablyfine\\{name}") in runs
        assert ("schtasks", "/Delete", "/TN", f"provablyfine\\{name}", "/F") in runs
    assert _text(_only_write(dry, MAIN)) == ORIGINAL
    assert any("Restart-Service -Name 'sshd'" in argv[-1] for argv in runs)
    assert ("net", "user", "pf-auth", "/delete") in runs
    removed = [a for a in dry.actions if isinstance(a, ops.Remove)]
    assert [a.path for a in removed] == [
        MAIN + ".pf-backup",
        "C:\\ProgramData\\ssh\\sshd_config.d\\10-pf.conf",
        "C:\\ProgramData\\ssh\\pf_ca.pub",
        "C:\\ProgramData\\ssh\\ssh_host_ecdsa_key.cert",
        "C:\\ProgramData\\ssh\\ssh_host_ed25519_key.cert",
        "C:\\ProgramData\\ssh\\ssh_host_rsa_key.cert",
        "C:\\ProgramData\\pf",
        "C:\\ProgramData\\pf-deadlines",
        "C:\\ProgramData\\pf-bastion",
        "C:\\ProgramData\\pf-kill-requests",
        "C:\\ProgramData\\pf-live-events",
    ]
    assert removed[-5].recursive
    assert removed[-4].recursive
    assert removed[-3].recursive
    assert removed[-2].recursive
    assert removed[-1].recursive


def test_uninit_ignores_tasks_that_are_not_there(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path)
    dry = _dry(tmp_path)
    win32.Windows(PF).uninit(dry, _settings())
    tolerant = [a.argv for a in dry.actions if isinstance(a, ops.Run) and not a.check]
    assert ("schtasks", "/Delete", "/TN", "provablyfine\\host-bastion", "/F") in tolerant
    assert ("net", "user", "pf-auth", "/delete") in tolerant


def test_uninit_leaves_a_user_that_pf_did_not_create(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path, marker=None)
    dry = _dry(tmp_path)
    win32.Windows(PF).uninit(dry, _settings())
    assert not [argv for argv in _runs(dry) if argv[0] == "net"]


def test_uninit_does_not_delete_a_user_the_marker_does_not_name_safely(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path, marker="x; Remove-Item C:\\")
    dry = _dry(tmp_path)
    win32.Windows(PF).uninit(dry, _settings())
    assert not [argv for argv in _runs(dry) if argv[0] == "net"]


def test_uninit_does_not_restart_sshd_when_it_never_had_the_block(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path, config=ORIGINAL)
    dry = _dry(tmp_path)
    win32.Windows(PF).uninit(dry, _settings())
    assert not _writes(dry, MAIN)
    assert not [argv for argv in _runs(dry) if "Restart-Service" in argv[-1]]


def test_uninit_does_not_restart_sshd_into_a_configuration_it_rejects(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path)
    dry = _dry(tmp_path, sshd_test=ops.QueryResult(255, "", "bad"))
    win32.Windows(PF).uninit(dry, _settings())
    assert not [argv for argv in _runs(dry) if "Restart-Service" in argv[-1]]


def test_uninit_refuses_an_unsafe_service_name(tmp_path: pathlib.Path) -> None:
    _created_host(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        win32.Windows(PF).uninit(_dry(tmp_path), _settings(sshd_service="a b"))


def test_sshd_needs_no_reload_for_new_host_certificates(tmp_path: pathlib.Path) -> None:
    dry = _dry(tmp_path)
    win32.Windows(PF).reload_sshd(dry)
    assert dry.actions == []


def test_the_defaults_live_under_programdata() -> None:
    assert win32.DEFAULTS.host_keys_dir == ntpath.join(win32.PROGRAM_DATA, "ssh")
    assert win32.DEFAULTS.sshd_config_drop_in == ntpath.join(win32.PROGRAM_DATA, "ssh", "sshd_config.d", "10-pf.conf")
    assert win32.DEFAULTS.auth_user == "pf-auth"
    assert not win32.DEFAULTS.ca_pub_path.startswith("/")
