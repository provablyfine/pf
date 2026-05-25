import getpass
import os

from .. import jwk, ssh


def generate_and_save_key() -> tuple[jwk.Private, str]:
    """Generate ed25519 key, prompt passphrase, save encrypted to ~/.ssh/, add to agent for 60s."""
    key = jwk.Private.generate_ed25519()
    fingerprint = key.public().ssh_fingerprint()

    safe = fingerprint.removeprefix("SHA256:").replace("/", "-").replace("+", "_")[:16]
    path = os.path.expanduser(f"~/.ssh/pf_{safe}")

    while True:
        pw = getpass.getpass(f"Passphrase for new key ({path}): ")
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw == pw2:
            break
        print("Passphrases do not match, try again.", flush=True)

    passphrase = pw.encode() if pw else None
    data = key.to_openssh(passphrase)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)

    print(f"Account key saved to {path}", flush=True)

    try:
        ssh_agent = ssh.agent.Client()
        ssh_agent.add(key, comment="pf-account", lifetime=60)
    except Exception:
        print(f"SSH agent unavailable; run: ssh-add {path}", flush=True)

    return key, fingerprint
