import logging
import time

import fastapi
import fastapi.responses

from ... import ssh
from .. import app_db, converters, grant, model, responses, schemas, signature
from ..context import ctx

logger = logging.getLogger(__name__)

router = fastapi.APIRouter(prefix="/ssh")


def _read_current(type: app_db.SigningKeyType, staging_period: int):
    now = int(time.time())
    return model.signing_key.read_all(
        ctx.app_db.signing_key.columns.valid_after <= now - staging_period,
        ctx.app_db.signing_key.columns.valid_before > now,
        type=type,
    )


@router.post(
    "/host/certificate",
    status_code=200,
    dependencies=[fastapi.Depends(signature.verify_session)],
    responses={400: responses.PROBLEM, 403: responses.PROBLEM},
)
def sign_host_certificate(data: schemas.ssh.SSHHostCertificateRequest) -> schemas.ssh.SSHHostCertificateResponse:
    caller = ctx.app_db.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated

    signers = _read_current(app_db.SigningKeyType.HOST, ctx.config.host_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())

    certificates: list[ssh.cert.Cert] = []
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

    return schemas.ssh.SSHHostCertificateResponse(certificates=[converters.cert_to_schema(c) for c in certificates])


@router.post(
    "/user/certificate",
    status_code=200,
    dependencies=[fastapi.Depends(signature.verify_session)],
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def sign_user_certificate(data: schemas.ssh.SSHUserCertificateRequest) -> schemas.ssh.SSHUserCertificateResponse:
    caller = ctx.app_db.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated
    host = model.identity.read_one(name=data.hostname)
    if host is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Unknown host"))

    ssh_shell_checker = grant.Grants.create().ssh_shell(host.id, host.tag_id_list, host.boundary_id_list)
    ssh_port_forward_checker = grant.Grants.create().ssh_port_forward(host.id, host.tag_id_list, host.boundary_id_list)
    ssh_command_checker = grant.Grants.create().ssh_command(host.id, host.tag_id_list, host.boundary_id_list)
    public_key = converters.public_from_schema(data.public_key)
    signers = _read_current(app_db.SigningKeyType.USER, ctx.config.user_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())

    match data.action:
        case "shell":
            perm = ssh_shell_checker.can(data.username)
            if perm is None:
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            cert = ssh.cert.Cert.create_user(
                public_key=public_key,
                serial_number=serial_number,
                identifier=f"{ctx.identity_id}:{caller.name}",
                principals=[f"{data.username}@{host.id}"],
                valid_after=now - 10,
                valid_before=now + ctx.config.user_certificate_lifetime,
                critical_options=ssh.cert.CriticalOptions(force_command=None),
                extensions=ssh.cert.Extensions(
                    permit_pty=True,
                    permit_user_rc=True,
                    permit_port_forwarding=False,
                    permit_x11_forwarding=perm.permit_x11_forwarding,
                    permit_agent_forwarding=perm.permit_agent_forwarding,
                ),
                signer=signer.key,
            )
        case "port-forwarding":
            if not ssh_port_forward_checker.can(data.username):
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            cert = ssh.cert.Cert.create_user(
                public_key=public_key,
                serial_number=serial_number,
                identifier=f"{ctx.identity_id}:{caller.name}",
                principals=[f"{data.username}@{host.id}"],
                valid_after=now - 10,
                valid_before=now + ctx.config.user_certificate_lifetime,
                critical_options=ssh.cert.CriticalOptions(force_command=None),
                extensions=ssh.cert.Extensions(
                    permit_pty=False,
                    permit_user_rc=False,
                    permit_port_forwarding=True,
                    permit_x11_forwarding=False,
                    permit_agent_forwarding=False,
                ),
                signer=signer.key,
            )
        case "command":
            if data.command is None:
                raise responses.ProblemHTTPException(
                    responses.problem_response(status_code=400, title="command required for action=command")
                )
            if not ssh_command_checker.can(data.username, data.command):
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            cert = ssh.cert.Cert.create_user(
                public_key=public_key,
                serial_number=serial_number,
                identifier=f"{ctx.identity_id}:{caller.name}",
                principals=[f"{data.username}@{host.id}"],
                valid_after=now - 10,
                valid_before=now + ctx.config.user_certificate_lifetime,
                critical_options=ssh.cert.CriticalOptions(force_command=data.command),
                extensions=ssh.cert.Extensions(
                    permit_pty=False,
                    permit_user_rc=False,
                    permit_port_forwarding=False,
                    permit_x11_forwarding=False,
                    permit_agent_forwarding=False,
                ),
                signer=signer.key,
            )

    serial_number += 1
    model.signing_key.update(signer.id, serial_number=serial_number)

    model.audit_log.create(
        "create-user-certificate",
        signing_key_id=signer.id,
        public_key=public_key.to_dict(),
        serial_number=cert.serial_number,
        principals=cert.principals,
        valid_after=cert.valid_after,
        valid_before=cert.valid_before,
        extensions=cert.extensions.to_dict(),
        critical_options=cert.critical_options.to_dict(),
    )

    logger.info(f"Generated certificate for username={data.username} action={data.action}")

    matching_bastions = model.bastion.read_matching()
    bastion_schema_list: list[schemas.bastion.Bastion] = []

    sessions = ctx.app_db.identity_session_key.read_all(
        identity_id=ctx.identity_id,
        is_revoked=False,
    )
    ip_address_list = [s.login_ip for s in sessions if s.login_ip and s.expires_at > now]

    if matching_bastions:
        grant_converter = converters.GrantConverter()
        for bastion in matching_bastions:
            bastion_schema = converters.bastion_to_schema(grant_converter, bastion)
            bastion_schema_list.append(bastion_schema)

    return schemas.ssh.SSHUserCertificateResponse(
        certificates=[converters.cert_to_schema(cert)],
        bastion_list=bastion_schema_list,
        ip_address_list=ip_address_list,
    )


@router.get(
    "/hosts",
    status_code=200,
    dependencies=[fastapi.Depends(signature.verify_session)],
)
def list_hosts() -> schemas.ssh.SSHHostsResponse:
    identities = model.identity.read_all()
    grants = grant.Grants.create()
    entries: list[schemas.ssh.SSHHostEntry] = []
    for identity in identities:
        shell_checker = grants.ssh_shell(identity.id, identity.tag_id_list, identity.boundary_id_list)
        for g in shell_checker.list_can():
            entries.append(
                schemas.ssh.SSHHostEntry(hostname=identity.name, type="shell", username_list=g.permission.username_list)
            )
        port_forward_checker = grants.ssh_port_forward(identity.id, identity.tag_id_list, identity.boundary_id_list)
        for g in port_forward_checker.list_can():
            entries.append(
                schemas.ssh.SSHHostEntry(hostname=identity.name, type="port", username_list=g.permission.username_list)
            )
        command_checker = grants.ssh_command(identity.id, identity.tag_id_list, identity.boundary_id_list)
        for g in command_checker.list_can():
            entries.append(
                schemas.ssh.SSHHostEntry(
                    hostname=identity.name,
                    type="command",
                    username_list=g.permission.username_list,
                    command_list=g.permission.command_list,
                )
            )
    return schemas.ssh.SSHHostsResponse(hosts=entries)


@router.get("/user/trusted-keys", status_code=200)
def read_user_trusted_keys() -> fastapi.responses.Response:
    now = int(time.time())
    signing_keys = model.signing_key.read_all(
        ctx.app_db.signing_key.columns.valid_before > now,
        type=app_db.SigningKeyType.USER,
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
        ctx.app_db.signing_key.columns.valid_before > now,
        type=app_db.SigningKeyType.HOST,
    )
    trusted_keys = [b"@cert-authority * " + signing_key.key.public().to_openssh() for signing_key in signing_keys]

    return fastapi.responses.Response(
        content=b"\n".join(trusted_keys),
        status_code=200,
        media_type="text/plain",
    )
