import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
@pytest.mark.skipif(not shutil.which("socat"), reason="socat not found")
def test_ssh_bastion(sshd, api, ssh_agent, bastion_server):
    utils.run_cram(
        "tests/ssh_bastion.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
            "BASTION_PORT": str(bastion_server.port),
        },
    )
