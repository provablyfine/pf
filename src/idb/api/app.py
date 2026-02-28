import time
import logging
import sys

import json

from .. import wa
from .. import jwk

from . import db
from . import openapi
from . import model
from . import signature
from . import middleware
from . import crypto_policy
from . import endpoints
from .context import ctx


logger = logging.getLogger(__name__)


def directory_endpoint(request: wa.Request) -> wa.Response:
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
        'login': f'{request.app.config.base_url}/idb/login',
        'boundary': f'{request.app.config.base_url}/idb/boundary',
        'tag': f'{request.app.config.base_url}/idb/tag',
        'role': f'{request.app.config.base_url}/idb/role',
        'identity': f'{request.app.config.base_url}/idb/identity',
        'ssh': f'{request.app.config.base_url}/idb/ssh',
    })


def create_keys(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, rotation_period: int, staging_period: int):
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


def initialize_endpoint(_: wa.Request) -> wa.Response:
    one = ctx.db.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )

    create_keys(
        db.SigningKeyType.HOST,
        jwk.KeyType.from_string(ctx.config.host_key_type),
        ctx.config.host_key_rotation_period,
        ctx.config.host_key_staging_period,
    )
    create_keys(
        db.SigningKeyType.USER,
        jwk.KeyType.from_string(ctx.config.user_key_type),
        ctx.config.user_key_rotation_period,
        ctx.config.user_key_staging_period,
    )

    root_boundary_id = model.boundary.create(
        name='root',
        description='The Root boundary is not a boundary at all.',
        ceiling_list=None,
        denied_list=[],
    )
    root_id = model.identity.create(
        name='root',
        boundary_id_list=[root_boundary_id],
        tag_id_list=[],
    )
    identity_grant_all = model.grant.Grant(
        filter=model.grant.IdentityFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.IdentityPermission(
            create=model.grant.IdentityCreatePermission(
                allowed_tag_id_list=None,
                required_boundary_id_list=None
            ),
            read=True,
            update=None,
            delete=True,
            add_tag_id_list=None,
            del_tag_id_list=None,
            invite_list=None,
        )
    )
    ssh_grant_all = model.grant.Grant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHPermission(
            force_command_list=None,
            username_list=None,
            permit_pty=True,
            permit_user_rc=True,
            permit_x11_forwarding=True,
            permit_agent_forwarding=True,
            permit_port_forwarding=True,
        )
    )
    tag_grant_all = model.grant.Grant(
        filter=model.grant.TagFilter(id=None),
        permission=model.grant.TagPermission(
            create=True,
            read=True,
            delete=True,
        ),
    )
    role_grant_all = model.grant.Grant(
        filter=model.grant.RoleFilter(id=None),
        permission=model.grant.BoundaryPermission(
            create=True,
            read=True,
            update=None,
            delete=True,
        ),
    )
    boundary_grant_all = model.grant.Grant(
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
        name='root',
        description=(
            'The "root" role identifies a user that is able to do anything. '
            'It is created once at startup and should be deleted once a proper '
            'permission model is deployed.'
        ),
        grant_list=all_grants
    )
    ctx.db.role_member.create(role_id=root_role_id, identity_id=root_id)

    identity_invitation_key_id = model.identity_invitation_key.create(
        identity_id=root_id,
        expiration_delay_s=600
    )

    return wa.JSONResponse(
        json=model.identity_invitation_key.format(identity_invitation_key_id),
        status_code=200
    )


@signature.verify_invitation
def accept_invitation_endpoint(request: wa.Request) -> wa.Response:
    data = json.loads(request.body)
    account_key = jwk.Public.from_dict(data['account_public_key'])
    crypto_policy.enforce_key_is_allowed(account_key)

    model.denylist.enforce_not_denied(account_key.thumbprint())

    # we can do the signature verification for the public account key
    signature.verify(request, f'account:{account_key.thumbprint()}', account_key)

    # if invitation has been accepted already, we do some checking to detect malevolent clients
    if request.state.invitation.is_accepted:
        if request.state.invitation.accepted_public_key_id == account_key.thumbprint():
            # The same key already accepted this invitation. This is probably some
            # kind of client-side or proxy retry
            return wa.Response(status_code=204)
        else:
            model.denylist.create(
                key_id=account_key.thumbprint(),
                identity_invitation_id=request.state.invitation.id,
            )
            return wa.ProblemResponse(status_code=403, title='Invitation was already accepted')

    # all verification passed. Bind the public account key with the identity
    # that was configured in the invitation.
    model.identity_invitation_key.accept(
        id=request.state.invitation.id,
        public_key_id=account_key.thumbprint(),
    )
    now = int(time.time())
    ctx.db.identity_account_key.create(
        id=account_key.thumbprint(),
        public_key=account_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None
    )
    return wa.Response(
        status_code=204
    )


@signature.verify_account
def login_endpoint(request: wa.Request) -> wa.Response:
    data = json.loads(request.body)
    session_key = jwk.Public.from_dict(data['session_public_key'])
    crypto_policy.enforce_key_is_allowed(session_key)

    model.denylist.enforce_not_denied(session_key.thumbprint())

    # we can do the signature verification for the public session key
    signature.verify(request, f'session:{session_key.thumbprint()}', session_key)

    # all verification passed. Bind the public session key with the identity
    # that was configured in the account
    now = int(time.time())
    ctx.db.identity_session_key.create(
        id=session_key.thumbprint(),
        public_key=session_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now+ctx.config.session_duration_s
    )

    return wa.Response(
        status_code=204
    )


def create(conf):
    match conf.log_level:
        case 'DEBUG':
            level = logging.DEBUG
        case 'INFO':
            level = logging.INFO
        case 'WARNING':
            level = logging.WARN
        case 'ERROR':
            level = logging.ERROR
    logging.basicConfig(stream=sys.stdout, level=level)
    db.create_tables(conf.database_url)
    middlewares = [
        wa.debug_store.DebugStoreMiddleware(wa.debug_store.InMemoryDebugStore()),
        wa.backtrace.BacktraceMiddleware(),
        openapi.create_middleware(conf.base_url),
        middleware.KekContext(),
        middleware.ConfigContext(),
        middleware.DbContext(),
    ]
    app = wa.Application(config=conf, middlewares=middlewares, lifespan=middleware.lifespan, debug=conf.debug)
    app.add('/idb/directory', directory_endpoint, methods=['GET'])
    app.add('/idb/initialize', initialize_endpoint, methods=['POST'])
    app.add('/idb/accept-invitation', accept_invitation_endpoint, methods=['POST'])
    app.add('/idb/login', login_endpoint, methods=['POST'])
    app.add('/idb/boundary', endpoints.boundary.create_endpoint, methods=['POST'])
    app.add('/idb/boundary', endpoints.boundary.list_endpoint, methods=['GET'])
    app.add('/idb/boundary/<int:boundary_id>', endpoints.boundary.update_endpoint, methods=['PATCH'])
    app.add('/idb/boundary/<int:boundary_id>', endpoints.boundary.delete_endpoint, methods=['DELETE'])
    app.add('/idb/tag', endpoints.tag.create_endpoint, methods=['POST'])
    app.add('/idb/tag', endpoints.tag.list_endpoint, methods=['GET'])
    app.add('/idb/tag/<int:tag_id>', endpoints.tag.delete_endpoint, methods=['DELETE'])
    app.add('/idb/role', endpoints.role.create_endpoint, methods=['POST'])
    app.add('/idb/role', endpoints.role.list_endpoint, methods=['GET'])
    app.add('/idb/role/<int:role_id>', endpoints.role.update_endpoint, methods=['PATCH'])
    app.add('/idb/role/<int:role_id>', endpoints.role.delete_endpoint, methods=['DELETE'])
    app.add('/idb/identity', endpoints.identity.create_endpoint, methods=['POST'])
    app.add('/idb/identity', endpoints.identity.list_endpoint, methods=['GET'])
    app.add('/idb/identity/self', endpoints.identity.read_self_endpoint, methods=['GET'])
    app.add('/idb/identity/<int:identity_id>', endpoints.identity.update_endpoint, methods=['PATCH'])
    app.add('/idb/identity/<int:identity_id>', endpoints.identity.delete_endpoint, methods=['DELETE'])
    app.add('/idb/identity/<int:identity_id>/invite', endpoints.identity.invite_endpoint, methods=['POST'])
    app.add('/idb/ssh/host/certificate', endpoints.ssh.sign_host_certificate, methods=['POST'])
    app.add('/idb/ssh/host/trusted-keys', endpoints.ssh.read_host_trusted_keys, methods=['GET'])
    #app.add('/idb/ssh/host/krl', endpoints.ssh.read_host_krl, methods=['GET'])
    app.add('/idb/ssh/user/certificate', endpoints.ssh.sign_user_certificate, methods=['POST'])
    app.add('/idb/ssh/user/trusted-keys', endpoints.ssh.read_user_trusted_keys, methods=['GET'])
    #app.add('/idb/ssh/user/krl', endpoints.ssh.read_user_krl, methods=['GET'])
    #app.add('/idb/ssh/user/allowed', endpoints.ssh.read_user_allowed, methods=['GET'])
    return app
