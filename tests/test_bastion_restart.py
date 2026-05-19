"""E2E test for bastion fdstore restart (systemd + fdstore fd recovery)."""

import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("socat"), reason="socat not found")
def test_bastion_fdstore_restart(api, ssh_agent, bastion_container):
    """Test bastion restart via systemctl with fdstore fd donation + recovery."""
    utils.run_cram(
        "tests/bastion_restart.t",
        {
            "API_PORT": str(api.port),
            "SSH_AUTH_SOCK": ssh_agent.socket,
            "BASTION_URL": "http://localhost",
            "BASTION_MAIN_SOCK": bastion_container.main_socket,
            "BASTION_CTRL_SOCK": bastion_container.control_socket,
            "CONTAINER_ID": bastion_container.container_id,
        },
    )
