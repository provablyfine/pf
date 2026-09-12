import os
import pathlib
import shutil
import socket
import sys
import tempfile

import pytest

from . import utils


def _free_port() -> int:
    # This is potentially unreliable since if multiple tests
    # did this, they all could try to use the same unix local port
    # in practice, though, it does not seem to be a problem
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not shutil.which("jq"), reason="jq not found")
@pytest.mark.parametrize(
    "filename",
    [
        "tags.t",
        "boundaries.t",
        "roles.t",
        "identity.t",
        "identity-posix.t",
        "permission.t",
        "access-control-tag.t.jinja",
        "access-control-tenant.t.jinja",
        "access-control-bastion.t.jinja",
        "access-control-identity.t",
        "access-control-identity-invite.t.jinja",
        "access-control-identity-create.t.jinja",
        "access-control-identity-delete.t.jinja",
        "access-control-identity-update.t.jinja",
        "access-control-identity-tag.t.jinja",
        "access-control-identity-read.t.jinja",
        "validation-error.t",
        "generic-exception-handler.t",
        "metrics.t",
        "bastion-crud.t",
        "tenant.t",
        "tenant-isolation.t",
        "auth.t",
        "audit-log.t",
        "access-control-audit-log.t",
        "login.t",
        "ping.t",
        "login_agent.t",
        "password-protected-key-read.t",
        "test-role-unique-name.t",
        "test-boundary-unique-name.t",
        "test-role-member-unique.t",
    ],
)
def test_pf_cram(api, filename):
    utils.run_cram(f"tests/{filename}", {"API_PORT": str(api.port), "API_LOG": str(api.log)})


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
def test_bastion_ssh(api, frps, sshd):
    utils.run_cram(
        "tests/bastion.t",
        {
            "API_PORT": str(api.port),
            "FRPS_BIND_PORT": str(frps.bind_port),
            "FRPS_CONNECT_PORT": str(frps.connect_port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_ADDRESS": str(sshd.host_address),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
            "LOCAL_FORWARD_PORT": str(_free_port()),
        },
    )


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
@pytest.mark.skipif(not shutil.which("jq"), reason="jq not found")
def test_ssh(sshd, api):
    utils.run_cram(
        "tests/ssh.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_ADDRESS": str(sshd.host_address),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
        },
    )


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
def test_ssh_session_deadline(sshd_pam, api):
    utils.run_cram(
        "tests/session-deadline.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd_pam.host_port),
            "SSHD_ADDRESS": str(sshd_pam.host_address),
            "SSHD_CONTAINER_ID": sshd_pam.container_id,
            "SSHD_KEYS_DIRECTORY": sshd_pam.keys_directory,
        },
    )


@pytest.mark.skipif(sys.platform == "win32", reason="cram is posix only")
@pytest.mark.skipif(not shutil.which("uv"), reason="uv not found")
def test_login_under_uv_run(api):
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    utils.run_cram("tests/login-uv.t", {"API_PORT": str(api.port), "REPO_ROOT": str(repo_root)})


def test_password_protected_key_create(api, tmp_path: pathlib.Path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    utils.run_cram(
        "tests/password-protected-key-create.t",
        {
            "API_PORT": str(api.port),
            "HOME": str(home),
        },
    )


def test_tmpdir_too_long(api):
    long = os.path.join(tempfile.gettempdir(), "pf-tmpdir-guard-" + "x" * 80)
    os.makedirs(long, exist_ok=True)
    utils.run_cram("tests/oracle-tmpdir-too-long.t", {"API_PORT": str(api.port), "TMPDIR": long})
