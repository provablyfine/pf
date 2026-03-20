import time

import fastapi
import fastapi.responses

from ... import jwk
from .. import converters, db, model, schemas
from ..context import ctx

router = fastapi.APIRouter()


def _create_keys(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, rotation_period: int, staging_period: int):
    now = int(time.time())

    # Create a  "current" key
    current_start = now - staging_period - 10
    current_end = current_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=current_start,
        valid_before=current_end,
    )
    # Create a  "staged" key
    staged_start = current_end - staging_period
    staged_end = staged_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=staged_start,
        valid_before=staged_end,
    )


@router.post("/pf/initialize")
def initialize_endpoint() -> fastapi.responses.Response:
    one = ctx.db.identity.read_one()
    if one is not None:
        return fastapi.responses.Response(status_code=204)

    _create_keys(
        db.SigningKeyType.HOST,
        jwk.KeyType.from_string(ctx.config.host_key_type),
        ctx.config.host_key_rotation_period,
        ctx.config.host_key_staging_period,
    )
    _create_keys(
        db.SigningKeyType.USER,
        jwk.KeyType.from_string(ctx.config.user_key_type),
        ctx.config.user_key_rotation_period,
        ctx.config.user_key_staging_period,
    )

    root_boundary_id = model.boundary.create(
        name="root",
        description="The Root boundary is not a boundary at all.",
        ceiling_list=None,
        denied_list=[],
    )
    root_id = model.identity.create(
        name="root",
        boundary_id_list=[root_boundary_id],
        tag_id_list=[],
    )
    identity_grant_all = model.grant.IdentityGrant(
        filter=model.grant.IdentityFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.IdentityPermission(
            create=model.grant.IdentityCreatePermission(
                allowed=True, allowed_tag_id_list=None, required_boundary_id_list=None
            ),
            read=True,
            update=None,
            delete=True,
            add_tag_id_list=None,
            del_tag_id_list=None,
            invite_list=None,
        ),
    )
    ssh_grant_all = model.grant.SSHGrant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHPermission(
            force_command_list=None,
            username_list=None,
            permit_pty=True,
            permit_user_rc=True,
            permit_x11_forwarding=True,
            permit_agent_forwarding=True,
            permit_port_forwarding=True,
        ),
    )
    tag_grant_all = model.grant.TagGrant(
        filter=model.grant.TagFilter(id=None),
        permission=model.grant.TagPermission(
            create=True,
            read=True,
            delete=True,
        ),
    )
    role_grant_all = model.grant.RoleGrant(
        filter=model.grant.RoleFilter(id=None),
        permission=model.grant.RolePermission(
            create=True,
            read=True,
            update=None,
            delete=True,
        ),
    )
    boundary_grant_all = model.grant.BoundaryGrant(
        filter=model.grant.BoundaryFilter(id=None),
        permission=model.grant.BoundaryPermission(
            create=True,
            read=True,
            update=None,
            delete=True,
        ),
    )
    all_grants = [
        identity_grant_all,
        ssh_grant_all,
        tag_grant_all,
        role_grant_all,
        boundary_grant_all,
    ]
    root_role_id = model.role.create(
        name="root",
        description=(
            'The "root" role identifies a user that is able to do anything. '
            "It is created once at startup and should be deleted once a proper "
            "permission model is deployed."
        ),
        grant_list=all_grants,
    )
    ctx.db.role_member.create(role_id=root_role_id, identity_id=root_id)

    identity_invitation_key_id = model.identity_invitation_key.create(identity_id=root_id, expiration_delay_s=600)
    identity_invitation = model.identity_invitation_key.read(identity_invitation_key_id)
    assert identity_invitation is not None, "key has just need created so it cannot possibly be None"

    return fastapi.responses.JSONResponse(
        content=schemas.InitializeResponse(key=converters.symmetric_to_schema(identity_invitation.key)).model_dump(),
        status_code=200,
    )
