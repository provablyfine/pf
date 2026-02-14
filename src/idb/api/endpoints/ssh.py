import time
import base64

import json

from ... import wa
from ... import jwk
from ... import ssh

from .. import db
from .. import model
from .. import signature
from .. import permission
from ..context import ctx


def _read_current(type: db.SigningKeyType, staging_period: int):
    now = int(time.time())
    return model.signing_key.read_all(
        ctx.db.signing_key.columns.valid_after <= now-staging_period,
        ctx.db.signing_key.columns.valid_before > now,
        type=type,
    )


@signature.verify_session
def sign_user_certificate(request: wa.Request) -> wa.Response:
    data = json.loads(request.body)
    caller = ctx.db.identity.read_one(id=ctx.identity_id)
    host = model.identity.read_one(name=data['hostname'])
    if host is None:
        return wa.ProblemResponse(status_code=404, title='Unknown host')

    identity_checker = permission.IdentityChecker(host.id, host.tag_id_list, host.boundary_id_list)

    verifier = permission.Verifier()
    ssh_shell_permissions = []
    ssh_exec_permissions = []
    ssh_forward_permissions = []
    for p in verifier.granted():
        checker = identity_checker.from_ssh_shell(p, username=data['username'])
        if checker is not None and verifier.is_allowed(checker):
            ssh_shell_permissions.append(p)
            continue
        checker = identity_checker.from_ssh_exec(p, username=data['username'])
        if checker is not None and verifier.is_allowed(checker):
            ssh_exec_permissions.append(p)
            continue
        checker = identity_checker.from_ssh_forward(p, username=data['username'])
        if checker is not None and verifier.is_allowed(checker):
            ssh_forward_permissions.append(p)
            continue

    public_key = jwk.Public.from_dict(data['public_key'])
    certificates = []
    signers = _read_current(db.SigningKeyType.USER, ctx.config.user_key_staging_period)
    signer = signers[0]
    serial_number = signer.serial_number
    now = int(time.time())

    permit_port_forwarding = len(ssh_forward_permissions) > 0

    for p in ssh_shell_permissions:
        cert = ssh.cert.Cert.create_user(
            public_key=public_key,
            serial_number=serial_number,
            identifier=f'{ctx.identity_id}:{caller.name}',
            principals=[f'{data["username"]}@{data["hostname"]}'],
            valid_after=now-10,
            valid_before=now+ctx.config.user_certificate_lifetime,
            critical_options=ssh.cert.CriticalOptions(),
            extensions=ssh.cert.Extensions(
                permit_port_forwarding=permit_port_forwarding,
                permit_pty=True,
                permit_x11_forwarding=p.get_bool_action_field('permit_x11_forwarding'),
                permit_agent_forwarding=p.get_bool_action_field('permit_agent_forwarding'),
            ),
            signer=signer.key,
        )
        serial_number += 1
        certificates.append(cert)

    for p in ssh_exec_permissions:
        cert = ssh.cert.Cert.create_user(
            public_key=public_key,
            serial_number=serial_number,
            identifier=f'{ctx.identity_id}:{caller.name}',
            principals=[f'{data["username"]}@{data["hostname"]}'],
            valid_after=now-10,
            valid_before=now+ctx.config.user_certificate_lifetime,
            critical_options=ssh.cert.CriticalOptions(
                force_command=p.get_action_field('command'),
            ),
            extensions=ssh.cert.Extensions(
                permit_port_forwarding=permit_port_forwarding,
                permit_pty=p.get_bool_action_field('permit_pty'),
                permit_x11_forwarding=p.get_bool_action_field('permit_x11_forwarding'),
                permit_agent_forwarding=p.get_bool_action_field('permit_agent_forwarding'),
            ),
            signer=signer.key,
        )
        serial_number += 1
        certificates.append(cert)

    if len(certificates) == 0 and permit_port_forwarding:
        cert = ssh.cert.Cert.create_user(
            public_key=public_key,
            serial_number=serial_number,
            identifier=f'{ctx.identity_id}:{caller.name}',
            principals=[f'{data["username"]}@{data["hostname"]}'],
            valid_after=now-10,
            valid_before=now+ctx.config.user_certificate_lifetime,
            critical_options=ssh.cert.CriticalOptions(),
            extensions=ssh.cert.Extensions(
                permit_port_forwarding=permit_port_forwarding,
            ),
            signer=signer.key,
        )
        serial_number += 1
        certificates.append(cert)

    model.signing_key.update(signer.id, serial_number=serial_number)

    for c in certificates:
        model.audit_log.create(
            'create-user-certificate',
            signing_key_id=signer.id,
            public_key=public_key.to_dict(),
            serial_number=c.serial_number,
            principals=c.principals,
            valid_after=c.valid_after,
            valid_before=c.valid_before,
            extensions=c.extensions.to_dict(),
            critical_options=c.critical_options.to_dict(),
        )

    return wa.JSONResponse(
        status_code=200,
        json={
            'certificates': [base64.b64encode(c.to_openssh()).decode('utf-8') for c in certificates]
        }
    )
