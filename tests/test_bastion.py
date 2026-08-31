import shutil
import socket

import pytest

from . import utils


def _free_port() -> int:
    # This is potentially unreliable since if multiple tests
    # did this, they all could try to use the same unix local port
    # in practice, though, it does not seem to be a problem
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
def test_bastion_ssh(api, frps, sshd, ssh_agent):
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
            "SSH_AUTH_SOCK": ssh_agent.socket,
            "LOCAL_FORWARD_PORT": str(_free_port()),
        },
    )
