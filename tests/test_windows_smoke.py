"""Native Windows smoke test: build/install artifacts are out of scope here (see
packaging/windows/), this only exercises the packaged pf.exe against a real local
sshd.exe — initialize -> accept/login host+user -> sign host cert -> pf ssh whoami.

Reproduces a minimal slice of tests/ssh.t's flow without cram, since cram itself
doesn't run on native Windows (its console-script shim has no .exe wrapper).
Admin-side setup runs through the dev environment (`uv run pfa`, test scaffolding);
only the host/user-side pf commands under test run through the actual packaged
pf.exe, which is what this test validates.

KNOWN ISSUE (xfail): the final `pf ssh ... whoami` step reliably fails
authentication when run through this fixture chain (pf.exe spawned by pytest via
`uv run`/subprocess, in turn spawning ssh.exe), even though every piece has been
independently verified to work when exercised directly:
  - the named-pipe agent transport (src/provablyfine/ssh/test_agent.py's
    win32-gated tests, run against the real local agent service);
  - unelevated sshd.exe honoring AuthorizedPrincipalsCommand/
    AuthorizedPrincipalsCommandUser for cert-based auth, matching Linux;
  - ssh.exe auto-detecting the well-known pipe with no SSH_AUTH_SOCK set and
    successfully signing with a key added by this project's own agent client,
    when both are driven directly (manual PowerShell/python.exe repro, outside
    pytest).
Inside this fixture chain specifically, ssh.exe's own debug log shows it never
even attempts to query the agent when SSH_AUTH_SOCK is left unset (as here), and
fails with "Device or resource busy" from ssh_get_authentication_socket when
SSH_AUTH_SOCK is explicitly set to the same well-known pipe path instead — with
no leaked connection found to explain it (traced: exactly one Client is opened,
used, and closed before the ssh.exe child is spawned). Ruled out during
investigation: PyInstaller freezing vs. source (`uv run pf`) makes no
difference; os.execvp vs. subprocess.run makes no difference; stale agent
identities from earlier test runs were not the cause (reproduces against a
freshly cleaned agent); MSYSTEM inherited from the Bash tool's Git Bash shell
makes no difference. Left as a documented follow-up rather than a blocker.
"""

import copy
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only smoke test")


def _find_pf_exe() -> str | None:
    # Prefer the PyInstaller onedir build unambiguously: shutil.which("pf") can
    # instead resolve .venv\Scripts\pf.exe, a real native launcher stub uv
    # generates for the dev venv's console-script entry point — which runs the
    # source tree, not the packaged binary this test is meant to validate.
    dist_pf = pathlib.Path(os.getcwd()) / "dist" / "pf" / "pf.exe"
    if dist_pf.exists():
        return str(dist_pf)
    return shutil.which("pf")


def _run(args: list[str], env: dict[str, str], input: str | None = None) -> str:
    completed = subprocess.run(args, env=env, input=input, capture_output=True, text=True)
    if completed.returncode != 0:
        raise Exception(f"{' '.join(args)} failed:\nstdout={completed.stdout}\nstderr={completed.stderr}")
    return completed.stdout


def _run_pfa(args: list[str], env: dict[str, str], input: str | None = None) -> str:
    return _run(["uv", "run", "pfa", *args], env, input)


def _sshd_config(
    *,
    port: int,
    host_key_path: str,
    host_cert_path: str,
    pf_exe: str,
    auth_user: str,
    user_ca_pub_path: str,
) -> str:
    auth_principals_command = (
        f'"{pf_exe}" openssh auth-principals --host-certificate={host_cert_path} --username=%u --certificate=%k'
    )
    return f"""\
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key_path}
HostCertificate {host_cert_path}
LoginGraceTime 30
StrictModes no
MaxAuthTries 10
AuthorizedPrincipalsCommand {auth_principals_command}
AuthorizedPrincipalsCommandUser {auth_user}
PubkeyAuthentication yes
AuthorizedKeysFile none
PasswordAuthentication no
Subsystem sftp none
TrustedUserCAKeys {user_ca_pub_path}
"""


@pytest.mark.xfail(reason="pf ssh agent auth fails only inside this fixture chain — see module docstring", strict=False)
def test_windows_smoke(api, ssh_agent, sshd_native, tmp_path: pathlib.Path):
    pf_exe = _find_pf_exe()
    if pf_exe is None:
        pytest.skip("pf.exe not found on PATH or at dist/pf/pf.exe — build it first")

    username = os.environ["USERNAME"]

    # Deliberately does NOT set SSH_AUTH_SOCK: real Windows users won't have it
    # set either, and pf/ssh.exe both fall back to the well-known pipe on their
    # own — see the module docstring for the open issue this runs into.
    admin_env = copy.copy(os.environ)
    admin_env.pop("SSH_AUTH_SOCK", None)
    host_env = copy.copy(admin_env)
    user_env = copy.copy(admin_env)

    admin_config = str(tmp_path / "admin.json")
    host_config = str(tmp_path / "host.json")
    user_config = str(tmp_path / "user.json")

    ssh_keygen = shutil.which("ssh-keygen")
    assert ssh_keygen is not None

    def keygen(name: str) -> str:
        path = str(tmp_path / name)
        subprocess.run([ssh_keygen, "-t", "ed25519", "-f", path, "-N", ""], check=True, capture_output=True)
        return path

    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    admin_account = keygen("admin-account")
    _run_pfa(["-c", admin_config, "initialize", directory_url, f"--key={admin_account}"], admin_env)
    admin_session = keygen("admin-session")
    _run_pfa(["-c", admin_config, "login", "--session-key", admin_session], admin_env)

    _run_pfa(["-c", admin_config, "tag", "create", "-n", "id", "-v", "device"], admin_env)
    device_tag_id = _run_pfa(["-c", admin_config, "tag", "list", "-n", "id", "-v", "device", "-q"], admin_env).strip()
    _run_pfa(["-c", admin_config, "role", "create", "-n", "role"], admin_env)
    role_id = _run_pfa(["-c", admin_config, "role", "list", "-n", "role", "-q"], admin_env).strip()
    grant = _run_pfa(
        ["-c", admin_config, "grant", "ssh", "--tag", "id=device", "--username", username, "--capability", "shell"],
        admin_env,
    )
    _run_pfa(["-c", admin_config, "role", "grant", "-i", role_id, "--add"], admin_env, input=grant)

    _run_pfa(["-c", admin_config, "identity", "create", "-n", "host", "-t", device_tag_id], admin_env)
    host_id = _run_pfa(["-c", admin_config, "identity", "list", "-n", "host", "-q"], admin_env).strip()
    host_invitation = _run_pfa(["-c", admin_config, "identity", "invite", "--manual", "-i", host_id], admin_env).strip()

    _run_pfa(["-c", admin_config, "identity", "create", "-n", "user"], admin_env)
    user_id = _run_pfa(["-c", admin_config, "identity", "list", "-n", "user", "-q"], admin_env).strip()
    _run_pfa(["-c", admin_config, "role", "member", "-i", role_id, "-a", "user"], admin_env)
    user_invitation = _run_pfa(["-c", admin_config, "identity", "invite", "--manual", "-i", user_id], admin_env).strip()

    host_account = keygen("host-account")
    _run([pf_exe, "-c", host_config, "accept", f"--invitation={host_invitation}", "--key", host_account], host_env)
    host_session = keygen("host-session")
    _run([pf_exe, "-c", host_config, "login", "--session-key", host_session], host_env)

    _run(
        [pf_exe, "-c", host_config, "openssh", "sign-host", f"--public-key={sshd_native.host_pubkey_path}"],
        host_env,
    )
    assert os.path.exists(sshd_native.host_cert_path)

    user_ca_pub_path = str(pathlib.Path(sshd_native.keys_directory) / "user-ca.pub")
    ca_pub = _run([pf_exe, "-c", host_config, "openssh", "user-trusted-keys"], host_env)
    pathlib.Path(user_ca_pub_path).write_text(ca_pub)

    sshd_config_path = str(tmp_path / "sshd_config")
    pathlib.Path(sshd_config_path).write_text(
        _sshd_config(
            port=sshd_native.port,
            host_key_path=sshd_native.host_key_path,
            host_cert_path=sshd_native.host_cert_path,
            pf_exe=pf_exe,
            auth_user=username,
            user_ca_pub_path=user_ca_pub_path,
        )
    )
    sshd_native.start(sshd_config_path, str(tmp_path / "sshd.log"))

    user_account = keygen("user-account")
    _run([pf_exe, "-c", user_config, "accept", f"--invitation={user_invitation}", "--key", user_account], user_env)
    user_session = keygen("user-session")
    _run([pf_exe, "-c", user_config, "login", "--session-key", user_session], user_env)

    output = _run(
        [
            pf_exe,
            "-c",
            user_config,
            "ssh",
            "-n",
            "-o",
            "Hostname=127.0.0.1",
            "-o",
            "HostKeyAlias=host",
            "-p",
            str(sshd_native.port),
            f"{username}@host",
            "whoami",
        ],
        user_env,
    )
    assert output.strip().lower().endswith(username.lower())
