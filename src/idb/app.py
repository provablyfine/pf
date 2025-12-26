import json

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
    invitation = model.IdentityInvitation.from_id(request.state.dao, data['key_id'], request.app.state.kek)
    if invitation is None:
        return wa.ProblemResponse(status_code=400, title=f'Invitation does not exist', detail=data['key_id'])
    if invitation.is_accepted:
        return wa.ProblemResponse(status_code=400, title=f'Invitation was already accepted. Get a new one.')
    if invitation.is_expired:
        return wa.ProblemResponse(status_code=400, title=f'Invitation is expired. Get a new one.')

    key = jwk.Public.from_dict(data['account_public_key'])
    signature.verify(request, f'account:{key.thumbprint()}', key)

#    invitation.accept()
#    request.state.dao.identity_invitation.update(identity_invitation=invitation.serialize(request.app.state.kek)).where(id=invitation.id)
#    request.state.dao.identity_key.create(
#        
#    )
    print(data)
    #print(list(request.headers.items()))
    #pass
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
