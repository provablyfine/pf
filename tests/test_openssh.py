import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
@pytest.mark.skipif(not shutil.which("jq"), reason="jq not found")
def test_ssh(sshd, api, ssh_agent):
    utils.run_cram(
        "tests/ssh.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_ADDRESS": str(sshd.host_address),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
def test_ssh_session_deadline(sshd_pam, api, ssh_agent):
    utils.run_cram(
        "tests/session-deadline.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd_pam.host_port),
            "SSHD_ADDRESS": str(sshd_pam.host_address),
            "SSHD_CONTAINER_ID": sshd_pam.container_id,
            "SSHD_KEYS_DIRECTORY": sshd_pam.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
