from __future__ import annotations

import pathlib
import plistlib
import sys
import typing

import provablyfine_client as pfc
import pytest

from . import base, darwin, ops

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="host-init is POSIX-only")

INVITATION = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory?invitation=3qFA-_8Kx9mLp0o1"
DIRECTORY_URL = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory"
INJECTION_URL = "https://x.invalid/directory?invitation=k';touch /tmp/PWNED;#"
PF = "/opt/provablyfine/pf"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the macOS provider tests need POSIX file owners")


def _settings(**overrides: str | None) -> base.Settings:
    fields: dict[str, str | None] = {
        "invitation": INVITATION,
        "directory_url": DIRECTORY_URL,
        "host_keys_dir": "/etc/ssh",
        "ca_pub_path": "/etc/ssh/pf_ca.pub",
        "sshd_config_drop_in": "/etc/ssh/sshd_config.d/10-pf.conf",
        "auth_user": "nobody",
        "pf_binary": None,
    }
    fields.update(overrides)
    return base.Settings(**typing.cast("dict[str, typing.Any]", fields))


def _queries(
    *, remote_login: bool = True, access_group: bool = True, port: str = "22", bastion_account: str = ""
) -> typing.Callable[[typing.Sequence[str]], ops.QueryResult]:
    def query(argv: typing.Sequence[str]) -> ops.QueryResult:
        match list(argv):
            case ["launchctl", "print", "system/com.openssh.sshd"]:
                return ops.QueryResult(0 if remote_login else 113, "")
            case ["dseditgroup", "-o", "read", "com.apple.access_ssh"]:
                return ops.QueryResult(0 if access_group else 56, "")
            case ["sshd", "-T"]:
                return ops.QueryResult(0, f"port {port}\n")
            case ["dscl", ".", "-read", "/Users/_pfbastion", "RealName"]:
                if bastion_account == "foreign":
                    return ops.QueryResult(0, "RealName:\n someone else\n")
                if bastion_account == "ours":
                    return ops.QueryResult(0, "RealName:\n provablyfine bastion\n")
                return ops.QueryResult(56, "")
            case ["dscl", ".", "-list", "/Users", "UniqueID"]:
                return ops.QueryResult(0, "root 0\n_taken 450\nmathieu 501\n")
            case ["dscl", ".", "-list", "/Groups", "PrimaryGroupID"]:
                return ops.QueryResult(0, "wheel 0\n_taken2 451\n")
        return ops.QueryResult(127, "")

    return query


def _host(tmp_path: pathlib.Path) -> None:
    pf = tmp_path / "opt" / "provablyfine" / "pf"
    pf.parent.mkdir(parents=True)
    pf.write_text("#!/bin/sh\n")
    for path in (pf, pf.parent, pf.parent.parent):
        path.chmod(0o755)
    (tmp_path / "etc" / "ssh" / "sshd_config.d").mkdir(parents=True)
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text("Include /etc/ssh/sshd_config.d/*\n")
    (tmp_path / "etc" / "ssh" / "sshd_config.d" / "100-macos.conf").write_text("UsePAM yes\n")
    for key_type in ("ed25519", "ecdsa", "rsa"):
        (tmp_path / "etc" / "ssh" / f"ssh_host_{key_type}_key.cert").write_text("cert\n")


def _dry(
    tmp_path: pathlib.Path, *, remote_login: bool = True, access_group: bool = True, port: str = "22"
) -> ops.DryRunOps:
    query = _queries(remote_login=remote_login, access_group=access_group, port=port)
    return ops.DryRunOps(root=tmp_path, query=query)


def _init(
    tmp_path: pathlib.Path,
    settings: base.Settings | None = None,
    *,
    remote_login: bool = True,
    access_group: bool = True,
    port: str = "22",
) -> ops.DryRunOps:
    dry = _dry(tmp_path, remote_login=remote_login, access_group=access_group, port=port)
    darwin.Darwin(PF).init(dry, settings or _settings())
    return dry


def _written(dry: ops.DryRunOps, path: str) -> ops.WriteFile:
    found = [a for a in dry.actions if isinstance(a, ops.WriteFile) and a.path == path]
    assert len(found) == 1, f"{path} written {len(found)} times"
    return found[0]


def _runs(dry: ops.DryRunOps) -> list[tuple[str, ...]]:
    return [a.argv for a in dry.actions if isinstance(a, ops.Run)]


def test_init_runs_the_steps_in_order(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    assert dry.actions[:3] == [
        ops.MakeDir("/var/db/pf", 0o700),
        ops.MakeDir("/var/log/pf", 0o755),
        ops.MakeDir("/var/db/pf-deadlines", 0o700, "nobody"),
    ]
    for directory in ("pf-bastion", "pf-kill-requests", "pf-live-events"):
        assert ops.MakeDir(f"/var/db/{directory}", 0o700, "_pfbastion") in dry.actions
    assert _runs(dry) == [
        ("dscl", ".", "-create", "/Groups/_pfbastion"),
        ("dscl", ".", "-create", "/Groups/_pfbastion", "PrimaryGroupID", "452"),
        ("dscl", ".", "-create", "/Users/_pfbastion"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "UniqueID", "452"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "PrimaryGroupID", "452"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "UserShell", "/usr/bin/false"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "NFSHomeDirectory", "/var/empty"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "RealName", "provablyfine bastion"),
        ("dscl", ".", "-create", "/Users/_pfbastion", "IsHidden", "1"),
        (PF, "-c", "/var/db/pf/accept.json", "accept", f"--invitation={INVITATION}", "--key=/var/db/pf/account.key"),
        ("ssh-keygen", "-A"),
        (
            PF,
            "openssh",
            "host-refresh",
            "--config=/var/db/pf/config.json",
            "--host-keys-dir=/etc/ssh",
            "--ca-pub-path=/etc/ssh/pf_ca.pub",
            "--no-sshd-reload",
        ),
        ("launchctl", "bootstrap", "system", "/Library/LaunchDaemons/net.provablyfine.host-refresh.plist"),
        ("launchctl", "bootstrap", "system", "/Library/LaunchDaemons/net.provablyfine.host-bastion.plist"),
        ("launchctl", "bootstrap", "system", "/Library/LaunchDaemons/net.provablyfine.session-reaper.plist"),
    ]


def test_init_stores_a_fresh_account_key_that_a_dry_run_does_not_show(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    key = _written(dry, "/var/db/pf/account.key")
    assert key.mode == 0o600
    assert key.secret
    assert key.content.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert "PRIVATE KEY" not in dry.describe()
    assert _written(_init(tmp_path), "/var/db/pf/account.key").content != key.content


def test_init_writes_the_client_config_for_root_only(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    config = _written(_init(tmp_path), "/var/db/pf/config.json")
    assert config.content == (
        b'{"directory_url": "' + DIRECTORY_URL.encode() + b'", "account_key_file": "/var/db/pf/account.key"}\n'
    )
    assert config.mode == 0o600


def test_init_writes_the_sshd_drop_in_with_the_deadline_directory_and_no_pam_block(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    assert _written(dry, "/etc/ssh/sshd_config.d/10-pf.conf").content.decode() == (
        "TrustedUserCAKeys /etc/ssh/pf_ca.pub\n"
        "HostCertificate /etc/ssh/ssh_host_ecdsa_key.cert\n"
        "HostCertificate /etc/ssh/ssh_host_ed25519_key.cert\n"
        "HostCertificate /etc/ssh/ssh_host_rsa_key.cert\n"
        f"AuthorizedPrincipalsCommand {PF} openssh auth-principals"
        " --host-certificate=/etc/ssh/ssh_host_ed25519_key.cert --username=%u --certificate=%k"
        " --deadline-dir=/var/db/pf-deadlines\n"
        "AuthorizedPrincipalsCommandUser nobody\n"
        "PubkeyAuthentication yes\n"
    )
    assert not [a for a in dry.actions if isinstance(a, ops.WriteFile) and "pam" in a.path]


def _service(dry: ops.DryRunOps, label: str) -> dict[str, typing.Any]:
    loaded = plistlib.loads(_written(dry, f"/Library/LaunchDaemons/{label}.plist").content)
    return typing.cast("dict[str, typing.Any]", loaded)


def test_init_installs_the_refresh_job(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    job = _service(_init(tmp_path), "net.provablyfine.host-refresh")
    assert job == {
        "Label": "net.provablyfine.host-refresh",
        "ProgramArguments": [
            PF,
            "openssh",
            "host-refresh",
            "--config=/var/db/pf/config.json",
            "--host-keys-dir=/etc/ssh",
            "--ca-pub-path=/etc/ssh/pf_ca.pub",
        ],
        "RunAtLoad": True,
        "StartInterval": 86400,
        "StandardOutPath": "/var/log/pf/host-refresh.log",
        "StandardErrorPath": "/var/log/pf/host-refresh.log",
    }


def test_init_installs_the_bastion_job_with_the_ssh_port(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    job = _service(_init(tmp_path, port="2222"), "net.provablyfine.host-bastion")
    assert job["ProgramArguments"] == [
        PF,
        "--config",
        "/var/db/pf-bastion/config.json",
        "bastion",
        "register",
        "--port",
        "2222",
        "--live-events-dir=/var/db/pf-live-events",
        "--kill-dir=/var/db/pf-kill-requests",
    ]
    assert job["KeepAlive"] is True
    assert job["UserName"] == "_pfbastion"
    assert job["StandardOutPath"] == "/var/db/pf-bastion/host-bastion.log"
    assert "StartInterval" not in job


def test_init_installs_the_session_reaper_job(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    job = _service(_init(tmp_path), "net.provablyfine.session-reaper")
    assert job["ProgramArguments"] == [
        PF,
        "openssh",
        "session-reaper",
        "--deadline-dir=/var/db/pf-deadlines",
        "--kill-dir=/var/db/pf-kill-requests",
        "--live-dir=/var/db/pf-live-events",
    ]
    assert job["KeepAlive"] is True


def test_init_leaves_remote_login_alone_when_it_is_on(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, remote_login=True)
    assert not [argv for argv in _runs(dry) if "enable" in argv]
    assert not [a for a in dry.actions if isinstance(a, ops.Note) and "Remote Login" in a.text]


def test_init_tries_to_turn_on_remote_login_when_it_is_off(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, remote_login=False)
    assert ("launchctl", "enable", "system/com.openssh.sshd") in _runs(dry)
    assert ("launchctl", "bootstrap", "system", "/System/Library/LaunchDaemons/ssh.plist") in _runs(dry)
    assert [a for a in dry.actions if isinstance(a, ops.Note) and "Remote Login" in a.text]
    tolerant = [a.argv for a in dry.actions if isinstance(a, ops.Run) and not a.check]
    assert ("launchctl", "enable", "system/com.openssh.sshd") in tolerant


def test_init_warns_that_ssh_logins_may_be_limited_to_a_group(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    notes = [a.text for a in _init(tmp_path, access_group=True).actions if isinstance(a, ops.Note)]
    assert len(notes) == 1
    assert "com.apple.access_ssh" in notes[0]
    assert "dseditgroup" in notes[0]
    assert not [a for a in _init(tmp_path, access_group=False).actions if isinstance(a, ops.Note)]


def test_init_asks_for_the_installer_package_when_pf_is_not_installed(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="installer package"):
        darwin.Darwin(None).init(dry, _settings())
    assert dry.actions == []


def test_init_refuses_a_pf_that_group_members_can_change(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "opt" / "provablyfine").chmod(0o775)
    dry = _dry(tmp_path)
    with pytest.raises(
        pfc.exceptions.UI, match=r"/opt/provablyfine/pf is not a correct install: /opt/provablyfine can be written"
    ):
        darwin.Darwin(PF).init(dry, _settings())
    assert dry.actions == []


def test_init_refuses_a_pf_that_is_not_executable(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "opt" / "provablyfine" / "pf").chmod(0o644)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="not an executable file"):
        darwin.Darwin(PF).init(dry, _settings())
    assert dry.actions == []


def test_init_uses_the_pf_given_on_the_command_line(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    other = tmp_path / "opt" / "provablyfine" / "other"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    dry = _dry(tmp_path)
    darwin.Darwin(None).init(dry, _settings(pf_binary="/opt/provablyfine/other"))
    assert ("/opt/provablyfine/other", "-c") == next(r for r in _runs(dry) if r[0] != "dscl")[:2]


def test_init_still_checks_the_pf_given_on_the_command_line(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "opt" / "provablyfine").chmod(0o775)
    with pytest.raises(pfc.exceptions.UI, match="is not a correct install"):
        darwin.Darwin(None).init(_dry(tmp_path), _settings(pf_binary=PF))


@pytest.mark.parametrize("directive", ["TrustedUserCAKeys /other.pub", "AuthorizedPrincipalsCommand /bin/x"])
def test_init_changes_nothing_when_sshd_already_sets_a_conflicting_directive(
    tmp_path: pathlib.Path, directive: str
) -> None:
    _host(tmp_path)
    (tmp_path / "etc" / "ssh" / "sshd_config.d" / "50-other.conf").write_text(directive + "\n")
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="conflicting sshd directive"):
        darwin.Darwin(PF).init(dry, _settings())
    assert dry.actions == []


@pytest.mark.parametrize("field", ["host_keys_dir", "ca_pub_path", "sshd_config_drop_in", "auth_user"])
@pytest.mark.parametrize("value", ["/etc/ssh\nPermitRootLogin yes", "/etc/ssh with space", "/etc/$HOME"])
def test_init_refuses_values_that_cannot_be_written_safely(tmp_path: pathlib.Path, field: str, value: str) -> None:
    _host(tmp_path)
    dry = _dry(tmp_path)
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        darwin.Darwin(PF).init(dry, _settings(**{field: value}))
    assert dry.actions == []


def test_init_keeps_an_invitation_with_shell_syntax_as_one_argument(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, _settings(invitation=INJECTION_URL))
    accept = next(argv for argv in _runs(dry) if "accept" in argv)
    assert f"--invitation={INJECTION_URL}" in accept
    for argv in _runs(dry):
        assert argv[0] not in ("sh", "bash", "/bin/sh", "/bin/bash")
    written = "".join(a.content.decode(errors="replace") for a in dry.actions if isinstance(a, ops.WriteFile))
    assert "PWNED" not in written


def test_uninit_undoes_the_install(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(bastion_account="ours"))
    darwin.Darwin(PF).uninit(dry, _settings())
    assert _runs(dry) == [
        ("launchctl", "bootout", "system/net.provablyfine.host-refresh"),
        ("launchctl", "bootout", "system/net.provablyfine.host-bastion"),
        ("launchctl", "bootout", "system/net.provablyfine.session-reaper"),
        ("dscl", ".", "-delete", "/Users/_pfbastion"),
        ("dscl", ".", "-delete", "/Groups/_pfbastion"),
    ]
    assert all(not a.check for a in dry.actions if isinstance(a, ops.Run))
    assert [a for a in dry.actions if isinstance(a, ops.Remove)] == [
        ops.Remove("/Library/LaunchDaemons/net.provablyfine.host-refresh.plist"),
        ops.Remove("/Library/LaunchDaemons/net.provablyfine.host-bastion.plist"),
        ops.Remove("/Library/LaunchDaemons/net.provablyfine.session-reaper.plist"),
        ops.Remove("/etc/ssh/sshd_config.d/10-pf.conf"),
        ops.Remove("/etc/ssh/pf_ca.pub"),
        ops.Remove("/etc/ssh/ssh_host_ecdsa_key.cert"),
        ops.Remove("/etc/ssh/ssh_host_ed25519_key.cert"),
        ops.Remove("/etc/ssh/ssh_host_rsa_key.cert"),
        ops.Remove("/var/db/pf", True),
        ops.Remove("/var/db/pf-deadlines", True),
        ops.Remove("/var/db/pf-bastion", True),
        ops.Remove("/var/db/pf-kill-requests", True),
        ops.Remove("/var/db/pf-live-events", True),
    ]


def test_uninit_does_not_need_the_installed_package(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "opt" / "provablyfine" / "pf").unlink()
    darwin.Darwin(None).uninit(_dry(tmp_path), _settings())


def test_sshd_needs_no_reload(tmp_path: pathlib.Path) -> None:
    dry = _dry(tmp_path)
    darwin.Darwin(PF).reload_sshd(dry)
    assert dry.actions == []


def test_init_accepts_the_invitation_with_a_config_file_that_pf_can_write_and_removes_it(
    tmp_path: pathlib.Path,
) -> None:
    # `pf -c /dev/null accept` fails: pf reads the config as JSON and /dev/null is empty.
    _host(tmp_path)
    dry = _init(tmp_path)
    accept_index = next(i for i, a in enumerate(dry.actions) if isinstance(a, ops.Run) and "accept" in a.argv)
    accept = dry.actions[accept_index]
    assert isinstance(accept, ops.Run)
    assert "/dev/null" not in accept.argv
    assert dry.actions[accept_index + 1] == ops.Remove("/var/db/pf/accept.json")
    assert dry.actions[accept_index + 2] == ops.Remove("/var/db/pf/accept.json.lock")


def test_the_deadline_directory_is_not_inside_the_root_only_state_directory() -> None:
    # The principals command runs as another user. It cannot reach a directory
    # below one that only root can enter, even when it owns the directory.
    assert not darwin.DEADLINE_DIR.startswith(darwin.STATE_DIR + "/")


def test_free_id_skips_ids_of_records_whose_names_contain_a_space() -> None:
    def query(argv: typing.Sequence[str]) -> ops.QueryResult:
        if list(argv) == ["dscl", ".", "-list", "/Users", "UniqueID"]:
            return ops.QueryResult(0, "root 0\nsome person 450\n")
        return ops.QueryResult(0, "wheel 0\n")

    assert darwin._free_id(ops.DryRunOps(query=query)) == 451  # pyright: ignore[reportPrivateUsage]


def test_init_refuses_a_pf_that_the_bastion_account_cannot_run(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "opt" / "provablyfine").chmod(0o750)
    with pytest.raises(
        pfc.exceptions.UI, match=r"is not a correct install: /opt/provablyfine is closed to other users"
    ):
        darwin.Darwin(PF).init(_dry(tmp_path), _settings())


def test_init_reuses_an_existing_bastion_account(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(bastion_account="ours"))
    darwin.Darwin(PF).init(dry, _settings())
    assert not any(argv[0] == "dscl" for argv in _runs(dry))


def test_init_refuses_an_account_that_pf_did_not_create(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(bastion_account="foreign"))
    with pytest.raises(pfc.exceptions.UI, match="pf did not create it"):
        darwin.Darwin(PF).init(dry, _settings())
    assert dry.actions == []


@pytest.mark.parametrize(("state", "deleted"), [("ours", True), ("foreign", False), ("", False)])
def test_uninit_deletes_only_an_account_that_pf_created(tmp_path: pathlib.Path, state: str, deleted: bool) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(bastion_account=state))
    darwin.Darwin(PF).uninit(dry, _settings())
    assert (("dscl", ".", "-delete", "/Users/_pfbastion") in _runs(dry)) is deleted


def test_bastion_key_and_config_belong_to_the_bastion_account(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    assert _written(dry, "/var/db/pf-bastion/account.key").owner == "_pfbastion"
    assert _written(dry, "/var/db/pf-bastion/config.json").owner == "_pfbastion"
    assert _written(dry, "/var/db/pf/account.key").owner is None
