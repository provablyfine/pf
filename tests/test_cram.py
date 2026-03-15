import pytest

from . import utils


@pytest.mark.parametrize("filename", [
    "tags.t",
    "boundaries.t",
    "roles.t",
    "identity.t",
    "permission.t",
    "access-control-tag.t.jinja",
    "access-control-identity.t",
    "access-control-identity-invite.t.jinja",
    "access-control-identity-create.t.jinja",
    "access-control-identity-delete.t.jinja",
    "access-control-identity-update.t.jinja",
    "access-control-identity-tag.t.jinja",
    "access-control-identity-read.t.jinja",
])
def test_pf_cram(api, filename):
    utils.run_cram(f'tests/{filename}', {'API_PORT': str(api.port)})


@pytest.mark.parametrize("filename", [
    "ssh-certificates.t.jinja",
    "ssh-ecdsa-certificates.t.jinja",
    "ssh-keys.t",
])
def test_ssh_cram(filename):
    utils.run_cram(f'tests/{filename}', {})

@pytest.mark.parametrize("filename", [
    "ssh-agent-keys.t.jinja",
])
def test_ssh_agent_cram(filename, ssh_agent):
    utils.run_cram(f'tests/{filename}', {'SSH_AUTH_SOCK': ssh_agent.socket})
