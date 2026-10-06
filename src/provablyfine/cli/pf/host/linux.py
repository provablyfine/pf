"""host-init for Linux hosts running systemd and PAM."""

from __future__ import annotations

import json
import os

import provablyfine_client as pfc

from . import base, common_steps, ops

STATE_DIR = "/var/lib/pf"
LOG_DIR = "/var/log/pf"
CREDENTIAL = f"{STATE_DIR}/account.cred"
CONFIG = f"{STATE_DIR}/config.json"
SYSTEMD_DIR = "/etc/systemd/system"
NM_DISPATCHER_DIR = "/etc/NetworkManager/dispatcher.d"
NM_DISPATCHER = f"{NM_DISPATCHER_DIR}/pf-host-refresh"
PAM_SSHD = "/etc/pam.d/sshd"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SYSTEMCTL = "/usr/bin/systemctl"
PF_DIRECTORIES = ("/usr/local/bin", "/usr/bin", "/bin")
PAM_BEGIN = "# BEGIN pf"
PAM_END = "# END pf"
CONFLICTING_DIRECTIVES = ("TrustedUserCAKeys", "AuthorizedPrincipalsCommand")

REFRESH_SERVICE = f"{SYSTEMD_DIR}/pf-host-refresh.service"
REFRESH_TIMER = f"{SYSTEMD_DIR}/pf-host-refresh.timer"
BASTION_SERVICE = f"{SYSTEMD_DIR}/pf-host-bastion.service"

_TIMER = """\
[Unit]
Description=Provably Fine SSH host certificate refresh timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
"""

_NM_DISPATCHER = """\
#!/bin/sh
case "$2" in
  up|connectivity-change)
    systemctl start pf-host-refresh.service
    ;;
esac
"""


def _find_pf(o: ops.Ops) -> str:
    for directory in PF_DIRECTORIES:
        candidate = f"{directory}/pf"
        if o.is_executable(candidate):
            return candidate
    raise pfc.exceptions.UI(f"pf binary not found in system PATH ({', '.join(PF_DIRECTORIES)})")


def _sshd_unit(o: ops.Ops) -> str:
    """Unit name of the SSH daemon: 'sshd' on Fedora, 'ssh' on Debian and Ubuntu."""
    result = o.query([SYSTEMCTL, "list-unit-files", "--no-legend", "sshd.service"])
    if result.returncode == 0 and any(line.startswith("sshd.service") for line in result.stdout.splitlines()):
        return "sshd"
    return "ssh"


def _ssh_port(o: ops.Ops) -> str:
    result = o.query(["sshd", "-T"])
    for line in result.stdout.splitlines():
        if line.startswith("port "):
            return line.split()[1]
    return "22"


def _host_certificates(o: ops.Ops, host_keys_dir: str) -> list[str]:
    certificates = o.glob(f"{host_keys_dir}/ssh_host_*_key.cert")
    if certificates:
        return certificates
    # Host-refresh writes one certificate next to each host public key.
    return [path.removesuffix(".pub") + ".cert" for path in o.glob(f"{host_keys_dir}/ssh_host_*_key.pub")]


def _credential_property() -> str:
    return f"--property=LoadCredentialEncrypted=account:{CREDENTIAL}"


def _reload_or_start(o: ops.Ops, unit: str) -> None:
    if o.query([SYSTEMCTL, "is-active", unit]).returncode == 0:
        o.run([SYSTEMCTL, "reload", unit])
    else:
        o.run([SYSTEMCTL, "enable", "--now", unit])


class Linux:
    def init(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        for what, value in (
            ("--host-keys-dir", s.host_keys_dir),
            ("--ca-pub-path", s.ca_pub_path),
            ("--sshd-config-drop-in", s.sshd_config_drop_in),
            ("--auth-user", s.auth_user),
        ):
            common_steps.require_plain(value, what)
        pf_bin = _find_pf(o)
        drop_in_dir = os.path.dirname(s.sshd_config_drop_in)

        conflict = common_steps.conflicting_directive(
            o, [SSHD_CONFIG, *o.list_dir(drop_in_dir)], CONFLICTING_DIRECTIVES
        )
        if conflict is not None:
            raise pfc.exceptions.UI(f"conflicting sshd directive '{conflict}' found; remove before initializing pf")
        pam = o.read_text(PAM_SSHD) or ""
        if PAM_BEGIN in pam.splitlines():
            raise pfc.exceptions.UI(f"pf PAM block already present in {PAM_SSHD}; remove before re-running host-init")

        o.make_dir(STATE_DIR, 0o700)
        o.make_dir(LOG_DIR, 0o755)
        o.run(
            ["systemd-creds", "encrypt", "--name=account", "-", CREDENTIAL],
            stdin=common_steps.new_account_key_pem(),
        )
        o.write_file(
            CONFIG,
            json.dumps({"directory_url": s.directory_url, "account_key_file": "$CREDENTIALS_DIRECTORY/account"}) + "\n",
            0o644,
        )

        under_credentials = ["systemd-run", "--pipe", "--wait", _credential_property()]
        o.run(
            [
                *under_credentials,
                pf_bin,
                "-c",
                "/dev/null",
                "accept",
                f"--invitation={s.invitation}",
                "--key=$CREDENTIALS_DIRECTORY/account",
            ]
        )
        o.run(["ssh-keygen", "-A"])
        o.run(
            [
                *under_credentials,
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
        drop_in = [f"TrustedUserCAKeys {s.ca_pub_path}"]
        drop_in += [f"HostCertificate {path}" for path in _host_certificates(o, s.host_keys_dir)]
        drop_in += [
            f"AuthorizedPrincipalsCommand {pf_bin} openssh auth-principals"
            f" --host-certificate={s.host_keys_dir}/ssh_host_ed25519_key.cert"
            " --username=%u --certificate=%k",
            f"AuthorizedPrincipalsCommandUser {s.auth_user}",
            "PubkeyAuthentication yes",
        ]
        o.write_file(s.sshd_config_drop_in, "\n".join(drop_in) + "\n", 0o644)

        pam_block = (
            f"{PAM_BEGIN}\n"
            f"session optional pam_exec.so {pf_bin} -d -d --log-filename={LOG_DIR}/session-deadline.log"
            f" openssh session-deadline --ca-pub-path={s.ca_pub_path}\n"
            f"{PAM_END}\n"
        )
        o.write_file(PAM_SSHD, common_steps.append_block(pam, pam_block), None)

        refresh_command = (
            f"{pf_bin} openssh host-refresh --config={CONFIG}"
            f" --host-keys-dir={s.host_keys_dir} --ca-pub-path={s.ca_pub_path}"
        )
        o.write_file(
            REFRESH_SERVICE,
            "[Unit]\n"
            "Description=Provably Fine SSH host certificate refresh\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={refresh_command}\n"
            f"LoadCredentialEncrypted=account:{CREDENTIAL}\n",
            0o644,
        )
        o.write_file(REFRESH_TIMER, _TIMER, 0o644)
        o.run([SYSTEMCTL, "daemon-reload"])
        o.run([SYSTEMCTL, "enable", "--now", "pf-host-refresh.timer"])

        _reload_or_start(o, _sshd_unit(o))

        o.write_file(
            BASTION_SERVICE,
            "[Unit]\n"
            "Description=Provably Fine bastion registration\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"LoadCredentialEncrypted=account:{CREDENTIAL}\n"
            f"ExecStart={pf_bin} --config {CONFIG} bastion register --port {_ssh_port(o)}\n"
            "Restart=on-failure\n"
            "RestartSec=30s\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
            0o644,
        )
        o.run([SYSTEMCTL, "daemon-reload"])
        o.run([SYSTEMCTL, "enable", "--now", "pf-host-bastion.service"])

        if o.exists(NM_DISPATCHER_DIR):
            o.write_file(NM_DISPATCHER, _NM_DISPATCHER, 0o755)

    def uninit(self, o: ops.Ops, settings: base.Settings) -> None:
        s = settings
        o.run([SYSTEMCTL, "disable", "--now", "pf-host-refresh.timer"], check=False)
        o.run([SYSTEMCTL, "stop", "pf-host-refresh.service"], check=False)
        o.remove(REFRESH_SERVICE)
        o.remove(REFRESH_TIMER)
        o.run([SYSTEMCTL, "disable", "--now", "pf-host-bastion.service"], check=False)
        o.remove(BASTION_SERVICE)
        o.remove(NM_DISPATCHER)
        o.run([SYSTEMCTL, "daemon-reload"])

        o.run([SYSTEMCTL, "stop", "pf-deadline-*.timer"], check=False)
        pam = o.read_text(PAM_SSHD)
        if pam is not None:
            o.write_file(PAM_SSHD, common_steps.remove_block(pam, PAM_BEGIN, PAM_END), None)

        o.remove(s.sshd_config_drop_in)
        o.remove(s.ca_pub_path)
        for certificate in o.glob(f"{s.host_keys_dir}/ssh_host_*_key.cert"):
            o.remove(certificate)
        o.remove(STATE_DIR, recursive=True)

        unit = _sshd_unit(o)
        if o.query([SYSTEMCTL, "is-active", unit]).returncode == 0:
            o.run([SYSTEMCTL, "reload", unit])

    def reload_sshd(self, o: ops.Ops) -> None:
        o.run([SYSTEMCTL, "reload", _sshd_unit(o)])
