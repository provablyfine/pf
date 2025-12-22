import contextlib

import starlette.applications
import starlette.responses
import starlette.routing
import databases
import cryptography.fernet

from . import config
from . import db
from . import dao_factory
from . import decorators
from . import openapi
from . import model
from . import base64url


async def idb_directory(request):
    return starlette.responses.JSONResponse({
        'initialize': f'{config.BASE_URL}/idb/initialize',
        'accept-invitation': f'{config.BASE_URL}/idb/accept-invitation',
    })


@decorators.transaction
async def idb_initialize(request):
    one = await request.state.dao.identity.read_one()
    if one is not None:
        return starlette.responses.Response(
            status_code=204
        )
    root_boundary = model.Boundary.create(name='Root Boundary', description='The Root boundary is not a boundary at all.')
    restricted_boundary = model.Boundary.create(name='Restricted Boundary', description='The Restricted boundary does not allow anything')
    for deny in ['identity:*', 'role:*', 'group:*', 'tag:*', 'boundary:*']:
        restricted_boundary.add_deny(deny)
    root = model.Identity.create(name='root', boundary_id=root_boundary.id)
    root_role = model.Role.create(name='root', description='The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.')
    root_role.add_permission('*:*')
    ii = model.IdentityInvitation.create(identity_id=root.id, expiration_delay_s=600)

    await request.state.dao.boundary.create(id=root_boundary.id, boundary=root_boundary.serialize())
    await request.state.dao.boundary.create(id=restricted_boundary.id, boundary=restricted_boundary.serialize())
    await request.state.dao.default.create(boundary_id=restricted_boundary.id)
    await request.state.dao.identity.create(id=root.id, identity=root.serialize())
    await request.state.dao.role.create(id=root_role.id, role=root_role.serialize())
    await request.state.dao.role_identity_grant.create(role_id=root_role.id, identity_id=root.id)
    await request.state.dao.identity_invitation.create(id=ii.id, identity_invitation=ii.serialize(request.app.state.kek))
    
    for o in [root_boundary, restricted_boundary, root, root_role, ii]:
        for log in o.audit_log:
            await request.state.dao.audit_log.create(log=log.serialize(None))
    return starlette.responses.JSONResponse(
        ii.format(),
        status_code=200
    )


@decorators.transaction
async def idb_accept_invitation(request) -> starlette.responses.Response:
    pass
#    return starlette.responses.Response(
#        status_code=204
#    )

@contextlib.asynccontextmanager
async def lifespan(app):
    database = databases.Database(config.DATABASE_URL)
    await database.connect()
    with open(config.KEK_FILENAME, 'rb') as f:
        kek = base64url.encode(f.read()) + '======'
        kek = cryptography.fernet.Fernet(kek)
    app.state.dao = dao_factory.create(database, db.metadata)
    app.state.database = database
    app.state.kek = kek
    yield
    await database.disconnect()


def create_application():
    db.create_tables(config.DATABASE_URL)
    acme = starlette.applications.Starlette(
        debug=config.DEBUG,
        routes=[
            starlette.routing.Route('/idb/directory', idb_directory, methods=['GET']),
            starlette.routing.Route('/idb/initialize', idb_initialize, methods=['POST']),
            starlette.routing.Route('/idb/accept-invitation', idb_accept_invitation, methods=['POST']),
            #starlette.routing.Route('/idb/identity/create', create_identity, methods=['POST']),
            #starlette.routing.Route('/idb/identity/list', list_identities, methods=['POST']),
            #starlette.routing.Route('/idb/identity/{identity_id}/update', update_identity, methods=['POST']),
            #starlette.routing.Route('/idb/role/create', create_role, methods=['POST']),
            #starlette.routing.Route('/idb/role/list', list_roles, methods=['POST']),
            #starlette.routing.Route('/idb/role/{role_id}/update', update_role, methods=['POST']),
            #starlette.routing.Route('/idb/group/create', create_group, methods=['POST']),
            #starlette.routing.Route('/idb/group/list', list_group, methods=['POST']),
            #starlette.routing.Route('/idb/group/{group_id}/update', update_group, methods=['POST']),
            #starlette.routing.Route('/idb/boundary/create', create_boundary, methods=['POST']),
            #starlette.routing.Route('/idb/boundary/list', list_boundary, methods=['POST']),
            #starlette.routing.Route('/idb/boundary/{boundary_id}/update', update_boundary, methods=['POST']),
            #starlette.routing.Route('/idb/boundary/{boundary_id}/set-default', set_default_boundary, methods=['POST']),
        ],
        lifespan=lifespan,
        middleware=openapi.create_middleware(),
    )
    return acme


app = create_application()
