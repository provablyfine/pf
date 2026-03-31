import time

import fastapi
import fastapi.responses

from ... import jwk
from .. import converters, dao_factory, db, dependencies, model, schemas
from ..context import ctx

router = fastapi.APIRouter()


def _create_keys(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, rotation_period: int, staging_period: int):
    now = int(time.time())

    current_start = now - staging_period - 10
    current_end = current_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=current_start,
        valid_before=current_end,
    )
    staged_start = current_end - staging_period
    staged_end = staged_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=staged_start,
        valid_before=staged_end,
    )


def _provision(allow_tenant_create: bool):
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

    tenant_grant_all = model.grant.TenantGrant(
        filter=model.grant.TenantFilter(id=None),
        permission=model.grant.TenantPermission(
            create=allow_tenant_create,
            read=True,
            delete=True,
            update=model.grant.TenantUpdatePermission(display_name=True, is_enabled=True),
        ),
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
    ssh_shell_grant_all = model.grant.SSHShellGrant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHShellPermission(
            username_list=["root"],
            permit_agent_forwarding=True,
            permit_x11_forwarding=True,
        ),
    )
    ssh_port_forwarding_grant_all = model.grant.SSHPortForwardingGrant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHPortForwardingPermission(username_list=["root"]),
    )
    ssh_command_grant_all = model.grant.SSHCommandGrant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHCommandPermission(username_list=["root"], command_list=[]),
    )
    tag_grant_all = model.grant.TagGrant(
        filter=model.grant.TagFilter(id=None),
        permission=model.grant.TagPermission(create=True, read=True, delete=True),
    )
    role_grant_all = model.grant.RoleGrant(
        filter=model.grant.RoleFilter(id=None),
        permission=model.grant.RolePermission(create=True, read=True, update=None, delete=True),
    )
    boundary_grant_all = model.grant.BoundaryGrant(
        filter=model.grant.BoundaryFilter(id=None),
        permission=model.grant.BoundaryPermission(create=True, read=True, update=None, delete=True),
    )
    auth_grant_all = model.grant.AuthGrant(
        filter=model.grant.AuthFilter(id=None),
        permission=model.grant.AuthPermission(create=True, read=True, update=None, delete=True),
    )

    if allow_tenant_create:
        ceiling_list = None
    else:
        # Sub-tenant ceiling: all grant types allowed EXCEPT tenant creation.
        # We must include ALL grant types here because the Checker's type-specific
        # filter function returns False for non-matching types, causing any(...)
        # to be False, which would block the operation.
        ceiling_list = [
            identity_grant_all,
            ssh_shell_grant_all,
            ssh_port_forwarding_grant_all,
            ssh_command_grant_all,
            tag_grant_all,
            role_grant_all,
            boundary_grant_all,
            tenant_grant_all,
            auth_grant_all,
        ]

    root_boundary_id = model.boundary.create(
        name="root",
        description="The Root boundary is not a boundary at all.",
        ceiling_list=ceiling_list,
        denied_list=[],
    )
    root_id = model.identity.create(
        name="root",
        boundary_id_list=[root_boundary_id],
        tag_id_list=[],
    )
    all_grants = [
        identity_grant_all,
        ssh_shell_grant_all,
        ssh_port_forwarding_grant_all,
        ssh_command_grant_all,
        tag_grant_all,
        role_grant_all,
        boundary_grant_all,
        tenant_grant_all,
        auth_grant_all,
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

    model.auth_config.create(
        name="default",
        description="Default HTTP signature authentication",
        tag_id_list=[],
        type="http_sig",
        config={},
    )


@router.post(
    "/initialize",
    status_code=200,
    response_model=schemas.InitializeResponse,
    responses={204: {"description": "Already initialized"}},
)
def initialize_endpoint(
    registry_dao: dao_factory.Dao = fastapi.Depends(dependencies.registry_dao),
) -> schemas.InitializeResponse | fastapi.responses.Response:
    tenant_row = registry_dao.tenant.read_one(id=ctx.tenant_id)
    assert tenant_row is not None

    if tenant_row.is_initialized:
        return fastapi.responses.Response(status_code=204)

    identity = ctx.db.identity.read_one(id=1)
    if identity is None:
        _provision(allow_tenant_create=tenant_row.owner_id is None)
        identity = ctx.db.identity.read_one(id=1)
        assert identity is not None

    identity_invitation_key_id = model.identity_invitation_key.create(identity_id=identity.id, expiration_delay_s=600)
    identity_invitation = model.identity_invitation_key.read(identity_invitation_key_id)
    assert identity_invitation is not None

    registry_dao.tenant.update(is_initialized=True).where(id=ctx.tenant_id)

    return schemas.InitializeResponse(key=converters.symmetric_to_schema(identity_invitation.key))
