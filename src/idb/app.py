import json
import time

from . import wa
from . import config
from . import db
from . import openapi
from . import model
from . import jwk
from . import signature
from . import middleware
from . import crypto_policy
from . import permissions
from .context import ctx


def idb_directory(request):
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
        'login': f'{request.app.config.base_url}/idb/login',
    })


def idb_initialize(_: wa.Request):
    one = ctx.db.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )
    all_grants = [
        permissions.identity.create_grant().to_dict(),
        permissions.role.create_grant().to_dict(),
        permissions.tag.create_grant().to_dict(),
        permissions.boundary.create_grant().to_dict(),
    ]
    # setup restricted boundary as default
    restricted_boundary_id = model.boundary.create(
        name='Restricted Boundary',
        description='The Restricted boundary does not allow anything',
        denies=all_grants,
    )
    ctx.db.default.create(boundary_id=restricted_boundary_id)

    # root user
    root_boundary_id = model.boundary.create(
        name='root',
        description='The Root boundary is not a boundary at all.',
        denies=[],
    )
    root_id = model.identity.create(
        name='root',
        boundaries=[root_boundary_id],
    )
    root_role_id = model.role.create(
        name='root',
        description="""The "root" role identifies a user that is able to do anything.
        It is created once at startup and should be deleted once a proper permission
        model is deployed.""",
        permissions=all_grants
    )
    ctx.db.role_grant.create(role_id=root_role_id, identity_id=root_id)

    # invitation for root user
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


@signature.verify_session
def idb_boundary_list(request) -> wa.Response:
    verifier = permissions.Verifier()
    boundaries = ctx.db.boundary.read_all()
    output = []
    for boundary in boundaries:
        request = verifier.create_boundary_request(instance=boundary, action='show')
        if verifier.is_allowed(request):
            output.append(boundary)
    return wa.JSONResponse(
        status_code=200,
        json={'boundaries': [{'id': boundary.id, 'denies': boundary.denies} for boundary in output]}
    )


@signature.verify_session
def idb_boundary_create(request) -> wa.Response:
    return wa.Response(
        status_code=400
    )


@signature.verify_session
def idb_boundary_read(request) -> wa.Response:
    return wa.Response(
        status_code=400
    )


@signature.verify_session
def idb_boundary_update(request) -> wa.Response:
    return wa.Response(
        status_code=400
    )


def create(filename):
    conf = config.Config.load(filename)
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
    app.add('/idb/boundary', idb_boundary_create, methods=['POST'])
    app.add('/idb/boundary', idb_boundary_list, methods=['GET'])
    app.add('/idb/boundary/<boundary_id:int>', idb_boundary_read, methods=['GET'])
    app.add('/idb/boundary/<boundary_id:int>', idb_boundary_update, methods=['PATCH'])
    return app
