from . import utils


def test_ssh(sshd, api, ssh_agent):
    utils.run_cram(
        "tests/ssh.t",
        {
            "API_PORT": str(api.port),
            "SSHD_PORT": str(sshd.host_port),
            "SSHD_CONTAINER_ID": sshd.container_id,
            "SSHD_KEYS_DIRECTORY": sshd.keys_directory,
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
