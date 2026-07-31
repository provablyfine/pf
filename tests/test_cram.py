import pytest

from . import utils


@pytest.mark.parametrize(
    "filename",
    [
        "tags.t",
        "boundaries.t",
        "roles.t",
        "identity.t",
        "identity-posix.t",
        "permission.t",
        "access-control-tag.t.jinja",
        "access-control-tenant.t.jinja",
        "access-control-bastion.t.jinja",
        "access-control-identity.t",
        "access-control-identity-invite.t.jinja",
        "access-control-identity-create.t.jinja",
        "access-control-identity-delete.t.jinja",
        "access-control-identity-update.t.jinja",
        "access-control-identity-tag.t.jinja",
        "access-control-identity-read.t.jinja",
        "validation-error.t",
        "generic-exception-handler.t",
        "metrics.t",
        "bastion-crud.t",
        "tenant.t",
        "tenant-isolation.t",
        "auth.t",
        "audit-log.t",
        "access-control-audit-log.t",
        "login.t",
        "ping.t",
    ],
)
def test_pf_cram(api, filename):
    utils.run_cram(f"tests/{filename}", {"API_PORT": str(api.port), "API_LOG": str(api.log)})


@pytest.mark.parametrize("api", [{"unix_mode": "standalone"}], indirect=True)
def test_identity_standalone_cram(api):
    utils.run_cram("tests/identity-standalone.t", {"API_PORT": str(api.port), "API_LOG": str(api.log)})
