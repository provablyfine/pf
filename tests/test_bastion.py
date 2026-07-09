import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
def test_bastion_ssh(api, frps, sshd, ssh_agent):
    utils.run_cram(
        "tests/bastion.t",
        {
            "API_PORT": str(api.port),
            "FRPS_BIND_PORT": str(frps.bind_port),
            "FRPS_CONNECT_PORT": str(frps.connect_port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
