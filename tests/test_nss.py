import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("ssh"), reason="ssh not found")
@pytest.mark.parametrize("api", [{"unix_mode": "standalone"}], indirect=True)
def test_nss(sshd_nss, api, ssh_agent):
    utils.run_cram(
        "tests/nss.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd_nss.host_port),
            "SSHD_ADDRESS": str(sshd_nss.host_address),
            "SSHD_CONTAINER_ID": sshd_nss.container_id,
            "SSHD_KEYS_DIRECTORY": sshd_nss.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
