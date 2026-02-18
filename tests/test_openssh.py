from . import utils


def test_ssh(sshd, api, ssh_agent):
    utils.run_cram('tests/idb-ssh.t', {
        'API_PORT': str(api.port),
        'SSHD_PORT': str(sshd.host_port),
        'USER_CA_PUBLIC_KEYS_FILENAME': sshd.user_ca_public_keys_filename,
        'SSH_AUTH_SOCK': ssh_agent.socket,
    })
