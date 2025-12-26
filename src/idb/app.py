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
from .context import ctx


def idb_directory(request):
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
    })


def idb_initialize(_: wa.Request):
    one = ctx.db.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )
    # setup restricted boundary as default
    restricted_denies = ['identity:*', 'role:*', 'group:*', 'tag:*', 'boundary:*']
    restricted_boundary_id = model.boundary.create(
        name='Restricted Boundary',
        description='The Restricted boundary does not allow anything',
        denies=restricted_denies,
    )
    ctx.db.default.create(boundary_id=restricted_boundary_id)

    # root user
    root_boundary_id = model.boundary.create(
        name='Root Boundary',
        description='The Root boundary is not a boundary at all.',
        denies=[],
    )
    root_id = model.identity.create(
        name='root',
        boundary_id=root_boundary_id,
    )
    root_role_id = model.role.create(
        name='root',
        description="""The "root" role identifies a user that is able to do anything.
        It is created once at startup and should be deleted once a proper permission
        model is deployed.""",
        permissions=['*:*']
    )
    ctx.db.role_identity_grant.create(role_id=root_role_id, identity_id=root_id)

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

    # is the requesting public key in a global denylist ?
    denylist_entry = ctx.db.public_key_denylist.read_one(public_key_id=account_key.thumbprint())
    if denylist_entry:
        model.audit_log.create_warning(type='identity-invitation-key-denylist', public_key_id=account_key.thumbprint())
        # Purposedly return an error that is not reality because the client is probably
        # malevolent
        return wa.ProblemResponse(status_code=403, title='Invitation was already accepted')

    # if invitation has been accepted already, we do some checking to detect malevolent clients
    if request.state.invitation.is_accepted:
        if request.state.invitation.accepted_public_key_id == account_key.thumbprint():
            # The same key already accepted this invitation. This is probably some
            # kind of client-side or proxy retry
            return wa.Response(status_code=204)
        else:
            ctx.db.public_key_denylist.create(key_id=account_key.thumbprint(), created_at=int(time.time()))
            model.audit_log.create_warning(
                type='identity-invitation-key-double-accept',
                identity_invitation_id=request.state.invitation.id,
                second_public_key_id=account_key.thumbprint()
            )
            return wa.ProblemResponse(status_code=403, title='Invitation was already accepted')

    # we can do the signature verification for the public account key
    signature.verify(request, f'account:{account_key.thumbprint()}', account_key)

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
    return app
