from __future__ import annotations

import argparse
import base64
import logging
import os
import subprocess
import time

from ... import jwk, ssh

logger = logging.getLogger(__name__)


def _cert_from_auth_info() -> ssh.cert.Cert | None:
    """The user certificate sshd authenticated this session with.

    sshd puts one PAM environment variable per authentication method used,
    named SSH_AUTH_INFO_0, SSH_AUTH_INFO_1, ... regardless of ExposeAuthInfo;
    pam_exec forwards the whole PAM environment to its child. Each line has
    the form "publickey <key-type> <base64>".
    """
    index = 0
    while True:
        line = os.environ.get(f"SSH_AUTH_INFO_{index}")
        if line is None:
            return None
        index += 1
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[0] != "publickey" or not parts[1].endswith("-cert-v01@openssh.com"):
            continue
        try:
            return ssh.serde.deserialize_cert(base64.b64decode(parts[2]))
        except Exception:
            logger.warning("failed to parse certificate from SSH_AUTH_INFO", exc_info=True)
            return None


def _trusted_fingerprints(ca_pub_path: str) -> set[str]:
    try:
        with open(ca_pub_path, "rb") as f:
            data = f.read()
    except OSError:
        logger.warning(f"could not read CA public key file={ca_pub_path}", exc_info=True)
        return set()
    fingerprints: set[str] = set()
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            fingerprints.add(jwk.Public.from_openssh(line).ssh_fingerprint())
        except Exception:
            logger.warning(f"unparseable line in CA public key file={ca_pub_path}", exc_info=True)
    return fingerprints


def _handle_close_session() -> None:
    cert = _cert_from_auth_info()
    if cert is None or cert.extensions.connection_id is None:
        return
    unit = f"pf-deadline-{cert.extensions.connection_id}.timer"
    subprocess.run(["/usr/bin/systemctl", "stop", unit], check=False, capture_output=True)  # noqa: S603


def _handle_open_session(ca_pub_path: str) -> None:
    cert = _cert_from_auth_info()
    if cert is None:
        return
    deadline = cert.extensions.session_deadline
    if deadline is None:
        # Unbounded grant: the common case, and the entire compatibility
        # story for hosts and grants that predate this feature. Checked
        # before the CA lookup below so this path stays cheap and silent.
        return
    if cert.signer_public_key.ssh_fingerprint() not in _trusted_fingerprints(ca_pub_path):
        # sshd already validated the certificate's signature against
        # TrustedUserCAKeys before PAM ran; this only guards against the
        # PAM environment somehow carrying a certificate signed by a CA we
        # do not (or no longer) trust.
        logger.warning("certificate signer is not a trusted CA; ignoring")
        return
    connection_id = cert.extensions.connection_id
    if connection_id is None:
        return
    logger.info(f"session_deadline decoded connection_id={connection_id} deadline={deadline}")

    session_id = os.environ.get("XDG_SESSION_ID")
    if not session_id:
        logger.warning("XDG_SESSION_ID not set; cannot enforce session deadline")
        return

    remaining = deadline - int(time.time())
    if remaining <= 0:
        subprocess.run(  # noqa: S603
            ["/usr/bin/loginctl", "terminate-session", session_id], check=False, capture_output=True
        )
        return

    subprocess.run(  # noqa: S603
        [
            "/usr/bin/systemd-run",
            "--collect",
            "--no-block",
            f"--on-active={remaining}",
            f"--unit=pf-deadline-{connection_id}",
            "/usr/bin/loginctl",
            "terminate-session",
            session_id,
        ],
        check=False,
        capture_output=True,
    )


def session_deadline_function(args: argparse.Namespace) -> None:
    """PAM session hook enforcing a certificate's session_deadline extension.

    Registered as `session optional pam_exec.so ... session-deadline` at the
    end of the sshd PAM session stack. Fails open unconditionally: every
    error is logged and swallowed here so the caller always sees a normal
    (exit 0) return, regardless of what pam_exec's "optional" control flag
    would have tolerated on its own. A bug in this hook must never lock
    users out of a host.
    """
    try:
        match os.environ.get("PAM_TYPE"):
            case "open_session":
                _handle_open_session(args.ca_pub_path)
            case "close_session":
                _handle_close_session()
            case _:
                pass
    except Exception:
        logger.warning("pf openssh session-deadline failed; failing open", exc_info=True)
