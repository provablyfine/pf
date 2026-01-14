import time
import logging
import sys

import json

from . import wa
from . import config
from . import db
from . import openapi
from . import model
from . import jwk
from . import signature
from . import middleware
from . import crypto_policy
from . import endpoints
from .context import ctx


def idb_directory(request):
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
        'login': f'{request.app.config.base_url}/idb/login',
        'boundary': f'{request.app.config.base_url}/idb/boundary',
        'tag': f'{request.app.config.base_url}/idb/tag',
    })


def idb_initialize(_: wa.Request):
    one = ctx.db.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )
    root_boundary_id = model.boundary.create(
        name='root',
        description='The Root boundary is not a boundary at all.',
        ceiling_list=[],
        denied_list=[],
    )
    root_id = model.identity.create(
        name='root',
        boundaries=[root_boundary_id],
    )
    all_grants = [
        permission_schema.identity.create_grant(),
        permission_schema.role.create_grant(),
        permission_schema.tag.create_grant(),
        permission_schema.boundary.create_grant(),
    ]
    root_role_id = model.role.create(
        name='root',
        description="""The "root" role identifies a user that is able to do anything.
        It is created once at startup and should be deleted once a proper permission
        model is deployed.""",
        permission_list=all_grants
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
def idb_accept_invitation(request) -> wa.Response:
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
def idb_login(request) -> wa.Response:
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


def create(filename):
    conf = config.Config.load(filename)
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
#        wa.backtrace.BacktraceMiddleware(),
        openapi.create_middleware(conf.base_url),
        middleware.KekContext(),
        middleware.ConfigContext(),
        middleware.DbContext(),
    ]
    app = wa.Application(config=conf, middlewares=middlewares, lifespan=middleware.lifespan, debug=conf.debug)
    app.add('/idb/directory', idb_directory, methods=['GET'])
    app.add('/idb/initialize', idb_initialize, methods=['POST'])
    app.add('/idb/accept-invitation', idb_accept_invitation, methods=['POST'])
    app.add('/idb/login', idb_login, methods=['POST'])
    app.add('/idb/boundary', endpoints.boundary.create, methods=['POST'])
    app.add('/idb/boundary', endpoints.boundary.list, methods=['GET'])
    app.add('/idb/boundary/<int:boundary_id>', endpoints.boundary.read, methods=['GET'])
    app.add('/idb/boundary/<int:boundary_id>', endpoints.boundary.update, methods=['PATCH'])
    app.add('/idb/boundary/<int:boundary_id>', endpoints.boundary.delete, methods=['DELETE'])
    app.add('/idb/tag', endpoints.tag.create, methods=['POST'])
    app.add('/idb/tag', endpoints.tag.list, methods=['GET'])
    app.add('/idb/tag/<int:tag_id>', endpoints.tag.read, methods=['GET'])
    app.add('/idb/tag/<int:tag_id>', endpoints.tag.update, methods=['PATCH'])
    app.add('/idb/tag/<int:tag_id>', endpoints.tag.delete, methods=['DELETE'])
    return app
