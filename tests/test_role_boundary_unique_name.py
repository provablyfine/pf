"""Test that role and boundary names are unique within a tenant."""

from . import utils


def test_role_name_uniqueness(api):
    """Test that multiple roles cannot have the same name."""
    utils.run_cram(
        "tests/test-role-unique-name.t",
        {"API_PORT": str(api.port), "API_LOG": str(api.log)},
    )


def test_boundary_name_uniqueness(api):
    """Test that multiple boundaries cannot have the same name."""
    utils.run_cram(
        "tests/test-boundary-unique-name.t",
        {"API_PORT": str(api.port), "API_LOG": str(api.log)},
    )


def test_role_member_uniqueness(api):
    """Test that the same identity cannot be added multiple times to a role."""
    utils.run_cram(
        "tests/test-role-member-unique.t",
        {"API_PORT": str(api.port), "API_LOG": str(api.log)},
    )
