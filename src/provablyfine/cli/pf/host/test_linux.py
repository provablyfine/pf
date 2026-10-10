from __future__ import annotations

import pathlib
import sys
import typing

import provablyfine_client as pfc
import pytest

from . import base, linux, ops

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="host-init is POSIX-only")

INVITATION = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory?invitation=3qFA-_8Kx9mLp0o1"
DIRECTORY_URL = "https://example.com/pf/t/00000000-0000-0000-0000-000000000001/directory"

# From the security review of the shell script: closes the single quote of the
# old template and runs a command as root during enrollment.
INJECTION_URL = "https://x.invalid/directory?invitation=k';touch /tmp/PWNED;#"

SYSTEMCTL = linux.SYSTEMCTL

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the Linux provider tests lay out a POSIX tree")


def _settings(**overrides: str) -> base.Settings:
    fields = {
        "invitation": INVITATION,
        "directory_url": DIRECTORY_URL,
        "host_keys_dir": "/etc/ssh",
        "ca_pub_path": "/etc/ssh/pf_ca.pub",
        "sshd_config_drop_in": "/etc/ssh/sshd_config.d/10-pf.conf",
        "auth_user": "nobody",
    }
    fields.update(overrides)
    return base.Settings(**fields)


def _queries(
    sshd_unit: str = "sshd",
    active: bool = True,
    port: str = "2222",
) -> typing.Callable[[typing.Sequence[str]], ops.QueryResult]:
    def query(argv: typing.Sequence[str]) -> ops.QueryResult:
        match list(argv):
            case [_, "list-unit-files", "--no-legend", "sshd.service"]:
                return ops.QueryResult(0, "sshd.service enabled enabled\n" if sshd_unit == "sshd" else "")
            case [_, "is-active", _]:
                return ops.QueryResult(0 if active else 3, "")
            case ["sshd", "-T"]:
                return ops.QueryResult(0, f"port {port}\nlistenaddress 0.0.0.0\n")
        return ops.QueryResult(127, "")

    return query


def _host(tmp_path: pathlib.Path, *, network_manager: bool = False, pam: str = "auth required pam_unix.so\n") -> None:
    pf = tmp_path / "usr" / "bin" / "pf"
    pf.parent.mkdir(parents=True)
    pf.write_text("#!/bin/sh\n")
    pf.chmod(0o755)
    (tmp_path / "etc" / "ssh" / "sshd_config.d").mkdir(parents=True)
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    for key_type in ("ed25519", "ecdsa", "rsa"):
        (tmp_path / "etc" / "ssh" / f"ssh_host_{key_type}_key.cert").write_text("cert\n")
    (tmp_path / "etc" / "pam.d").mkdir(parents=True)
    (tmp_path / "etc" / "pam.d" / "sshd").write_text(pam)
    if network_manager:
        (tmp_path / "etc" / "NetworkManager" / "dispatcher.d").mkdir(parents=True)


def _init(
    tmp_path: pathlib.Path,
    settings: base.Settings | None = None,
    queries: typing.Callable[[typing.Sequence[str]], ops.QueryResult] | None = None,
) -> ops.DryRunOps:
    dry = ops.DryRunOps(root=tmp_path, query=queries or _queries())
    linux.Linux().init(dry, settings or _settings())
    return dry


def _written(dry: ops.DryRunOps, path: str) -> ops.WriteFile:
    found = [a for a in dry.actions if isinstance(a, ops.WriteFile) and a.path == path]
    assert len(found) == 1, f"{path} written {len(found)} times"
    return found[0]


def _account_key_sent_to_systemd_creds(dry: ops.DryRunOps) -> bytes:
    for action in dry.actions:
        if isinstance(action, ops.Run) and action.argv[0] == "systemd-creds":
            assert action.stdin is not None
            return action.stdin
    raise AssertionError("systemd-creds was not run")


def _runs(dry: ops.DryRunOps) -> list[tuple[str, ...]]:
    return [a.argv for a in dry.actions if isinstance(a, ops.Run)]


def test_init_runs_the_steps_in_order(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    cred = "--property=LoadCredentialEncrypted=account:/var/lib/pf/account.cred"
    assert dry.actions[:2] == [ops.MakeDir("/var/lib/pf", 0o700), ops.MakeDir("/var/log/pf", 0o755)]
    assert _runs(dry) == [
        ("systemd-creds", "encrypt", "--name=account", "-", "/var/lib/pf/account.cred"),
        (
            "systemd-run",
            "--pipe",
            "--wait",
            cred,
            "/usr/bin/pf",
            "-c",
            "/var/lib/pf/accept.json",
            "accept",
            f"--invitation={INVITATION}",
            "--key=$CREDENTIALS_DIRECTORY/account",
        ),
        ("ssh-keygen", "-A"),
        (
            "systemd-run",
            "--pipe",
            "--wait",
            cred,
            "/usr/bin/pf",
            "openssh",
            "host-refresh",
            "--config=/var/lib/pf/config.json",
            "--host-keys-dir=/etc/ssh",
            "--ca-pub-path=/etc/ssh/pf_ca.pub",
            "--no-sshd-reload",
        ),
        (SYSTEMCTL, "daemon-reload"),
        (SYSTEMCTL, "enable", "--now", "pf-host-refresh.timer"),
        (SYSTEMCTL, "reload", "sshd"),
        (SYSTEMCTL, "daemon-reload"),
        (SYSTEMCTL, "enable", "--now", "pf-host-bastion.service"),
    ]


def test_init_encrypts_a_fresh_account_key_without_showing_it(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    first = _account_key_sent_to_systemd_creds(dry)
    assert first.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert "PRIVATE KEY" not in dry.describe()
    assert _account_key_sent_to_systemd_creds(_init(tmp_path)) != first


def test_init_writes_the_client_config(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    config = _written(_init(tmp_path), "/var/lib/pf/config.json")
    assert config.content == (
        b'{"directory_url": "' + DIRECTORY_URL.encode() + b'", "account_key_file": "$CREDENTIALS_DIRECTORY/account"}\n'
    )
    assert config.mode == 0o644


def test_init_writes_the_sshd_drop_in(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    drop_in = _written(_init(tmp_path), "/etc/ssh/sshd_config.d/10-pf.conf")
    assert drop_in.content.decode() == (
        "TrustedUserCAKeys /etc/ssh/pf_ca.pub\n"
        "HostCertificate /etc/ssh/ssh_host_ecdsa_key.cert\n"
        "HostCertificate /etc/ssh/ssh_host_ed25519_key.cert\n"
        "HostCertificate /etc/ssh/ssh_host_rsa_key.cert\n"
        "AuthorizedPrincipalsCommand /usr/bin/pf openssh auth-principals"
        " --host-certificate=/etc/ssh/ssh_host_ed25519_key.cert --username=%u --certificate=%k\n"
        "AuthorizedPrincipalsCommandUser nobody\n"
        "PubkeyAuthentication yes\n"
    )
    assert drop_in.mode == 0o644


def test_init_derives_host_certificates_from_public_keys_before_they_exist(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    for cert in (tmp_path / "etc" / "ssh").glob("*.cert"):
        cert.unlink()
    (tmp_path / "etc" / "ssh" / "ssh_host_ed25519_key.pub").write_text("pub\n")
    drop_in = _written(_init(tmp_path), "/etc/ssh/sshd_config.d/10-pf.conf").content.decode()
    assert "HostCertificate /etc/ssh/ssh_host_ed25519_key.cert\n" in drop_in


def test_init_adds_the_session_deadline_pam_block(tmp_path: pathlib.Path) -> None:
    _host(tmp_path, pam="auth required pam_unix.so")
    pam = _written(_init(tmp_path), "/etc/pam.d/sshd")
    assert pam.mode is None
    assert pam.content.decode() == (
        "auth required pam_unix.so\n"
        "# BEGIN pf\n"
        "session optional pam_exec.so /usr/bin/pf -d -d --log-filename=/var/log/pf/session-deadline.log"
        " openssh session-deadline --ca-pub-path=/etc/ssh/pf_ca.pub\n"
        "# END pf\n"
    )


def test_init_installs_the_refresh_units(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path)
    assert _written(dry, "/etc/systemd/system/pf-host-refresh.service").content.decode() == (
        "[Unit]\n"
        "Description=Provably Fine SSH host certificate refresh\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/pf openssh host-refresh --config=/var/lib/pf/config.json"
        " --host-keys-dir=/etc/ssh --ca-pub-path=/etc/ssh/pf_ca.pub\n"
        "LoadCredentialEncrypted=account:/var/lib/pf/account.cred\n"
    )
    assert _written(dry, "/etc/systemd/system/pf-host-refresh.timer").content.decode() == (
        "[Unit]\n"
        "Description=Provably Fine SSH host certificate refresh timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def test_init_installs_the_bastion_unit_with_the_ssh_port(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    unit = _written(_init(tmp_path), "/etc/systemd/system/pf-host-bastion.service").content.decode()
    assert unit == (
        "[Unit]\n"
        "Description=Provably Fine bastion registration\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "DynamicUser=yes\n"
        "LoadCredentialEncrypted=account:/var/lib/pf/account.cred\n"
        "LoadCredential=config:/var/lib/pf/config.json\n"
        "ExecStart=/usr/bin/pf --config ${CREDENTIALS_DIRECTORY}/config bastion register --port 2222\n"
        "Restart=on-failure\n"
        "RestartSec=30s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def test_init_defaults_to_port_22_when_sshd_does_not_say(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=lambda argv: ops.QueryResult(1, ""))
    linux.Linux().init(dry, _settings())
    assert b"--port 22\n" in _written(dry, "/etc/systemd/system/pf-host-bastion.service").content


@pytest.mark.parametrize(("unit", "expected"), [("sshd", "sshd"), ("ssh", "ssh")])
def test_init_picks_the_ssh_unit_name(tmp_path: pathlib.Path, unit: str, expected: str) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path, queries=_queries(sshd_unit=unit)))
    assert (SYSTEMCTL, "reload", expected) in runs


def test_init_starts_sshd_when_it_is_not_running(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    runs = _runs(_init(tmp_path, queries=_queries(active=False)))
    assert (SYSTEMCTL, "enable", "--now", "sshd") in runs
    assert (SYSTEMCTL, "reload", "sshd") not in runs


def test_init_installs_the_network_manager_hook_only_when_present(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    assert not [a for a in _init(tmp_path).actions if isinstance(a, ops.WriteFile) and "NetworkManager" in a.path]
    (tmp_path / "etc" / "NetworkManager" / "dispatcher.d").mkdir(parents=True)
    hook = _written(_init(tmp_path), "/etc/NetworkManager/dispatcher.d/pf-host-refresh")
    assert hook.mode == 0o755
    assert hook.content.startswith(b"#!/bin/sh\n")


def test_init_keeps_an_invitation_with_shell_syntax_as_one_argument(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = _init(tmp_path, _settings(invitation=INJECTION_URL))
    for argv in _runs(dry):
        assert argv[0] not in ("sh", "bash", "/bin/sh")
        assert not any("PWNED" in arg for arg in argv if not arg.startswith("--invitation="))
    accept = next(argv for argv in _runs(dry) if "accept" in argv)
    assert f"--invitation={INJECTION_URL}" in accept
    assert "PWNED" not in "".join(a.content.decode() for a in dry.actions if isinstance(a, ops.WriteFile))


@pytest.mark.parametrize(
    "field",
    ["host_keys_dir", "ca_pub_path", "sshd_config_drop_in", "auth_user"],
)
@pytest.mark.parametrize("value", ["/etc/ssh\nPermitRootLogin yes", "/etc/ssh with space", "/etc/ssh'x", "/etc/$HOME"])
def test_init_refuses_values_that_cannot_be_written_safely(tmp_path: pathlib.Path, field: str, value: str) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries())
    with pytest.raises(pfc.exceptions.UI, match="cannot be written safely"):
        linux.Linux().init(dry, _settings(**{field: value}))
    assert dry.actions == []


def test_init_changes_nothing_when_pf_is_not_installed_system_wide(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    (tmp_path / "usr" / "bin" / "pf").unlink()
    dry = ops.DryRunOps(root=tmp_path, query=_queries())
    with pytest.raises(pfc.exceptions.UI, match="pf binary not found"):
        linux.Linux().init(dry, _settings())
    assert dry.actions == []


@pytest.mark.parametrize("directive", ["TrustedUserCAKeys /other.pub", "AuthorizedPrincipalsCommand /bin/x"])
@pytest.mark.parametrize("where", ["sshd_config", "sshd_config.d/50-other.conf"])
def test_init_changes_nothing_when_sshd_already_sets_a_conflicting_directive(
    tmp_path: pathlib.Path, directive: str, where: str
) -> None:
    _host(tmp_path)
    target = tmp_path / "etc" / "ssh" / where
    target.write_text(target.read_text() if target.exists() else "")
    with open(target, "a") as f:
        f.write(directive + "\n")
    dry = ops.DryRunOps(root=tmp_path, query=_queries())
    with pytest.raises(pfc.exceptions.UI, match="conflicting sshd directive"):
        linux.Linux().init(dry, _settings())
    assert dry.actions == []


def test_init_changes_nothing_when_the_pam_block_is_already_there(tmp_path: pathlib.Path) -> None:
    _host(tmp_path, pam="auth required pam_unix.so\n# BEGIN pf\nsession optional x\n# END pf\n")
    dry = ops.DryRunOps(root=tmp_path, query=_queries())
    with pytest.raises(pfc.exceptions.UI, match="PAM block already present"):
        linux.Linux().init(dry, _settings())
    assert dry.actions == []


def test_uninit_undoes_the_install(tmp_path: pathlib.Path) -> None:
    _host(tmp_path, pam="auth required pam_unix.so\n# BEGIN pf\nsession optional x\n# END pf\nsession required y\n")
    dry = ops.DryRunOps(root=tmp_path, query=_queries())
    linux.Linux().uninit(dry, _settings())
    assert _written(dry, "/etc/pam.d/sshd").content.decode() == "auth required pam_unix.so\nsession required y\n"
    removed = [a.path for a in dry.actions if isinstance(a, ops.Remove)]
    assert removed == [
        "/etc/systemd/system/pf-host-refresh.service",
        "/etc/systemd/system/pf-host-refresh.timer",
        "/etc/systemd/system/pf-host-bastion.service",
        "/etc/NetworkManager/dispatcher.d/pf-host-refresh",
        "/etc/ssh/sshd_config.d/10-pf.conf",
        "/etc/ssh/pf_ca.pub",
        "/etc/ssh/ssh_host_ecdsa_key.cert",
        "/etc/ssh/ssh_host_ed25519_key.cert",
        "/etc/ssh/ssh_host_rsa_key.cert",
        "/var/lib/pf",
    ]
    assert dry.actions[-2] == ops.Remove("/var/lib/pf", True)
    assert _runs(dry)[-1] == (SYSTEMCTL, "reload", "sshd")


def test_uninit_ignores_units_that_are_not_there(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(active=False))
    linux.Linux().uninit(dry, _settings())
    tolerant = [a.argv for a in dry.actions if isinstance(a, ops.Run) and not a.check]
    assert (SYSTEMCTL, "disable", "--now", "pf-host-refresh.timer") in tolerant
    assert (SYSTEMCTL, "stop", "pf-deadline-*.timer") in tolerant
    assert (SYSTEMCTL, "reload", "sshd") not in _runs(dry)


def test_reload_sshd(tmp_path: pathlib.Path) -> None:
    _host(tmp_path)
    dry = ops.DryRunOps(root=tmp_path, query=_queries(sshd_unit="ssh"))
    linux.Linux().reload_sshd(dry)
    assert _runs(dry) == [(SYSTEMCTL, "reload", "ssh")]


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
    assert dry.actions[accept_index + 1] == ops.Remove("/var/lib/pf/accept.json")
    assert dry.actions[accept_index + 2] == ops.Remove("/var/lib/pf/accept.json.lock")
