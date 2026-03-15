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
