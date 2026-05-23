import shutil

from . import utils

import pytest


@pytest.mark.skipif(not shutil.which("socat"), reason="socat not found")
def test_bastion_reload(api, ssh_agent, bastion_server):
    """Test bastion snapshot/restore cycle via control socket."""
    utils.run_cram(
        "tests/bastion_reload.t",
        {
            "API_PORT": str(api.port),
            "SSH_AUTH_SOCK": str(ssh_agent.socket),
            "BASTION_PORT": str(bastion_server.port),
            "BASTION_CTRL_SOCK": str(bastion_server.control_socket),
        },
    )
