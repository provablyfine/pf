import logging
import time

import fastapi
import fastapi.responses

from ... import ssh
from .. import converters, db, grant, model, responses, schemas, signature
from ..context import ctx

logger = logging.getLogger(__name__)

router = fastapi.APIRouter(prefix="/pf/ssh")


def _read_current(type: db.SigningKeyType, staging_period: int):
    now = int(time.time())
    return model.signing_key.read_all(
        ctx.db.signing_key.columns.valid_after <= now - staging_period,
        ctx.db.signing_key.columns.valid_before > now,
        type=type,
    )


@router.post("/host/certificate", status_code=200, dependencies=[fastapi.Depends(signature.verify_session)])
def sign_host_certificate(data: schemas.SSHHostCertificateRequest) -> schemas.SSHHostCertificateResponse:
    caller = ctx.db.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated

    signers = _read_current(db.SigningKeyType.HOST, ctx.config.host_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())

    certificates = []
    for key in data.public_keys:
        public_key = converters.public_from_schema(key)
        cert = ssh.cert.Cert.create_host(
            public_key=public_key,
            serial_number=serial_number,
            identifier=f"{ctx.identity_id}:{caller.name}",
            principals=[caller.name],
            valid_after=now - 10,
            valid_before=now + ctx.config.host_certificate_lifetime,
            signer=signer.key,
        )
        serial_number += 1
        certificates.append(cert)

    for c in certificates:
        model.audit_log.create(
            "create-host-certificate",
            signing_key_id=signer.id,
            public_key=c.public_key.to_dict(),
            identifier=c.identifier,
            serial_number=c.serial_number,
            principals=c.principals,
            valid_after=c.valid_after,
            valid_before=c.valid_before,
        )

    return schemas.SSHHostCertificateResponse(certificates=[converters.cert_to_schema(c) for c in certificates])


@router.post("/user/certificate", status_code=200, dependencies=[fastapi.Depends(signature.verify_session)])
def sign_user_certificate(data: schemas.SSHUserCertificateRequest) -> schemas.SSHUserCertificateResponse:
    caller = ctx.db.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated
    host = model.identity.read_one(name=data.hostname)
    if host is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Unknown host"))

    grants = grant.Grants.create()
    grants_allowed = grants.ssh(host.id, host.tag_id_list, host.boundary_id_list).list_can_username(data.username)

    public_key = converters.public_from_schema(data.public_key)
    certificates = []
    signers = _read_current(db.SigningKeyType.USER, ctx.config.user_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())

    for allowed in grants_allowed:
        permission = allowed.permission
        if permission.force_command_list is None or len(permission.force_command_list) == 0:
            force_commands = [None]
        else:
            force_commands = permission.force_command_list
        for command in force_commands:
            cert = ssh.cert.Cert.create_user(
                public_key=public_key,
                serial_number=serial_number,
                identifier=f"{ctx.identity_id}:{caller.name}",
                principals=[f"{data.username}@{host.id}"],
                valid_after=now - 10,
                valid_before=now + ctx.config.user_certificate_lifetime,
                critical_options=ssh.cert.CriticalOptions(force_command=command),
                extensions=ssh.cert.Extensions(
                    permit_port_forwarding=permission.permit_port_forwarding,
                    permit_pty=permission.permit_pty,
                    permit_user_rc=permission.permit_user_rc,
                    permit_x11_forwarding=permission.permit_x11_forwarding,
                    permit_agent_forwarding=permission.permit_agent_forwarding,
                ),
                signer=signer.key,
            )
            serial_number += 1
            certificates.append(cert)

    logger.info(f"Generated certificates={len(certificates)} for username={data.username}")
    model.signing_key.update(signer.id, serial_number=serial_number)

    for c in certificates:
        model.audit_log.create(
            "create-user-certificate",
            signing_key_id=signer.id,
            public_key=public_key.to_dict(),
            serial_number=c.serial_number,
            principals=c.principals,
            valid_after=c.valid_after,
            valid_before=c.valid_before,
            extensions=c.extensions.to_dict(),
            critical_options=c.critical_options.to_dict(),
        )

    return schemas.SSHUserCertificateResponse(certificates=[converters.cert_to_schema(c) for c in certificates])


@router.get("/user/trusted-keys", status_code=200)
def read_user_trusted_keys() -> fastapi.responses.Response:
    now = int(time.time())
    signing_keys = model.signing_key.read_all(
        ctx.db.signing_key.columns.valid_before > now,
        type=db.SigningKeyType.USER,
    )
    trusted_keys = [signing_key.key.public().to_openssh() for signing_key in signing_keys]
    try:
        with open(ctx.config.user_extra_trusted_keys_filename, "rb") as f:
            trusted_keys.append(f.read())
    except Exception:
        pass

    return fastapi.responses.Response(
        content=b"\n".join(trusted_keys),
        status_code=200,
        media_type="text/plain",
    )


@router.get("/host/trusted-keys", status_code=200)
def read_host_trusted_keys() -> fastapi.responses.Response:
    now = int(time.time())
    signing_keys = model.signing_key.read_all(
        ctx.db.signing_key.columns.valid_before > now,
        type=db.SigningKeyType.HOST,
    )
    trusted_keys = [b"@cert-authority * " + signing_key.key.public().to_openssh() for signing_key in signing_keys]

    return fastapi.responses.Response(
        content=b"\n".join(trusted_keys),
        status_code=200,
        media_type="text/plain",
    )
