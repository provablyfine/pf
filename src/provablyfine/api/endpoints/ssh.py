import logging
import time
import typing
import uuid

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


def _deadline(now: int, ttl_list: list[int | None]) -> int | None:
    """The absolute unix-seconds deadline for a cert embedding the given capability TTLs.

    None entries are unbounded and skipped. If every entry is unbounded, the
    session itself is unbounded, so the deadline extension is omitted (None).
    Otherwise the tightest bound wins: the deadline governs the whole login
    session, which hosts every embedded capability.
    """
    bounded = [ttl for ttl in ttl_list if ttl is not None]
    if not bounded:
        return None
    return now + min(bounded)


@router.post(
    "/host/certificate",
    status_code=200,
    dependencies=[fastapi.Depends(signature.verify_session)],
    responses={400: responses.PROBLEM, 403: responses.PROBLEM},
)
def sign_host_certificate(data: schemas.ssh.SSHHostCertificateRequest) -> schemas.ssh.SSHHostCertificateResponse:
    caller = model.identity.read_one(id=ctx.identity_id)
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
    caller = model.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated
    host = model.identity.read_one(name=data.hostname)
    if host is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Unknown host"))

    checker = grant.Grants.create().ssh(host.id, host.tag_id_list, host.boundary_id_list)
    decision = checker.decide(data.username, caller.unix_username)
    public_key = converters.public_from_schema(data.public_key)
    signers = _read_current(app_db.SigningKeyType.USER, ctx.config.user_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())
    connection_id = str(uuid.uuid4())

    match data.action:
        case "shell":
            if model.grant.SSHCapability.SHELL not in decision.capabilities:
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            permit_pty = model.grant.SSHCapability.PTY in decision.capabilities
            permit_user_rc = model.grant.SSHCapability.USER_RC in decision.capabilities
            permit_port_forwarding = model.grant.SSHCapability.PORT_FORWARDING in decision.capabilities
            permit_x11_forwarding = model.grant.SSHCapability.X11_FORWARDING in decision.capabilities
            permit_agent_forwarding = model.grant.SSHCapability.AGENT_FORWARDING in decision.capabilities
            embedded_capabilities = {model.grant.SSHCapability.SHELL}
            if permit_pty:
                embedded_capabilities.add(model.grant.SSHCapability.PTY)
            if permit_user_rc:
                embedded_capabilities.add(model.grant.SSHCapability.USER_RC)
            if permit_port_forwarding:
                embedded_capabilities.add(model.grant.SSHCapability.PORT_FORWARDING)
            if permit_x11_forwarding:
                embedded_capabilities.add(model.grant.SSHCapability.X11_FORWARDING)
            if permit_agent_forwarding:
                embedded_capabilities.add(model.grant.SSHCapability.AGENT_FORWARDING)
            deadline = _deadline(now, [decision.capability_ttl[c] for c in embedded_capabilities])
            cert = ssh.cert.Cert.create_user(
                public_key=public_key,
                serial_number=serial_number,
                identifier=f"{ctx.identity_id}:{caller.name}",
                principals=[f"{data.username}@{host.id}"],
                valid_after=now - 10,
                valid_before=now + ctx.config.user_certificate_lifetime,
                critical_options=ssh.cert.CriticalOptions(force_command=None),
                extensions=ssh.cert.Extensions(
                    permit_pty=permit_pty,
                    permit_user_rc=permit_user_rc,
                    permit_port_forwarding=permit_port_forwarding,
                    permit_x11_forwarding=permit_x11_forwarding,
                    permit_agent_forwarding=permit_agent_forwarding,
                    session_deadline=deadline,
                    connection_id=connection_id,
                ),
                signer=signer.key,
            )
        case "port-forwarding":
            if model.grant.SSHCapability.PORT_FORWARDING not in decision.capabilities:
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            deadline = _deadline(now, [decision.capability_ttl[model.grant.SSHCapability.PORT_FORWARDING]])
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
                    session_deadline=deadline,
                    connection_id=connection_id,
                ),
                signer=signer.key,
            )
        case "command":
            if data.command is None:
                raise responses.ProblemHTTPException(
                    responses.problem_response(status_code=400, title="command required for action=command")
                )
            command_decision = decision.commands.permits(data.command)
            if command_decision is None:
                raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
            deadline = _deadline(now, [command_decision.ttl])
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
                    session_deadline=deadline,
                    connection_id=connection_id,
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

    logger.info(
        f"Generated certificate for username={data.username} action={data.action} connection_id={connection_id}"
    )

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


def _capability_entries(
    hostname: str,
    entry_type: typing.Literal["shell", "port"],
    capability: model.grant.SSHCapability,
    decisions: list[tuple[str | None, grant.SSHDecision]],
) -> list[schemas.ssh.SSHHostEntry]:
    """Entries for one capability, merged across usernames.

    A username of None means "any username the entries do not name", and the
    client renders it as "*". It gets its own entry because username_list
    cannot hold both concrete names and the wildcard.

    A named username and the wildcard can both appear for the same capability.
    That is deliberate: the two rows are not interchangeable, since a named
    username may hold capabilities the wildcard does not, or be denied ones the
    wildcard has. Neither row authorizes anything -- signing the certificate
    does.
    """
    entries: list[schemas.ssh.SSHHostEntry] = []
    named = [u for u, d in decisions if u is not None and capability in d.capabilities]
    if named:
        entries.append(schemas.ssh.SSHHostEntry(hostname=hostname, type=entry_type, username_list=named))
    if any(u is None and capability in d.capabilities for u, d in decisions):
        entries.append(schemas.ssh.SSHHostEntry(hostname=hostname, type=entry_type, username_list=None))
    return entries


@router.get(
    "/hosts",
    status_code=200,
    dependencies=[fastapi.Depends(signature.verify_session)],
)
def list_hosts() -> schemas.ssh.SSHHostsResponse:
    caller = model.identity.read_one(id=ctx.identity_id)
    assert caller is not None
    identities = model.identity.read_all()
    grants = grant.Grants.create()
    entries: list[schemas.ssh.SSHHostEntry] = []
    for identity in identities:
        checker = grants.ssh(identity.id, identity.tag_id_list, identity.boundary_id_list)
        decisions = checker.list_decisions(caller.unix_username)

        entries += _capability_entries(identity.name, "shell", model.grant.SSHCapability.SHELL, decisions)
        entries += _capability_entries(identity.name, "port", model.grant.SSHCapability.PORT_FORWARDING, decisions)

        # Command entries carry the permitted commands, which differ per
        # username, so they cannot be merged the way shell and port are.
        for username, decision in decisions:
            commands, any_command = decision.commands.candidates()
            if not commands and not any_command:
                continue
            entries.append(
                schemas.ssh.SSHHostEntry(
                    hostname=identity.name,
                    type="command",
                    username_list=None if username is None else [username],
                    command_list=None if any_command else commands,
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
