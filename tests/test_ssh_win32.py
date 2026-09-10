"""Windows `pf ssh` against a Linux sshd container, driven from pytest.

A deliberately small subset of all e2e tests. Everything `ssh.t` proves about
grants, boundaries and capabilities is platform-independent and already
covered on Linux; re-running it here would mostly re-test the API. What is
Windows-specific is the chain from a minted certificate through a named-pipe
oracle to a native `ssh.exe`, so that is what this exercises.
"""

import os
import shutil
import sys

import pytest

from . import cli as cli_support

_SYSTEM32_SSH = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "OpenSSH", "ssh.exe")


@pytest.mark.skipif(sys.platform != "win32", reason="tests the Windows pf ssh path")
@pytest.mark.skipif(not os.path.exists(_SYSTEM32_SSH), reason="native OpenSSH client not installed")
@pytest.mark.skipif(not shutil.which("podman"), reason="podman not found")
def test_ssh_win32(api, sshd, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cli = cli_support.Cli(work)
    cli_support.initialize(cli, api.port)

    # Forward slashes: a native Windows path that `pf` consumes as an argument.
    keys = sshd.keys_directory.replace("\\", "/")

    cli.run("pfa", "-c", "config.json", "tag", "create", "-n", "id", "-v", "device")
    tag_id = cli.run("pfa", "-c", "config.json", "tag", "list", "-n", "id", "-v", "device", "-q").strip()
    cli.run("pfa", "-c", "config.json", "role", "create", "-n", "role")
    role_id = cli.run("pfa", "-c", "config.json", "role", "list", "-n", "role", "-q").strip()
    grant = cli.run(
        "pfa", "-c", "config.json", "grant", "ssh",
        "--tag", "id=device", "--username", "root",
        "--capability", "shell", "pty", "user-rc", "port-forwarding",
    )  # fmt: skip
    # The `.t` piped this into the next command; `stdin=` is the same thing.
    cli.run("pfa", "-c", "config.json", "role", "grant", "-i", role_id, "--add", stdin=grant)

    cli.run("pfa", "-c", "config.json", "identity", "create", "-n", "host", "-t", tag_id)
    host_id = cli.run("pfa", "-c", "config.json", "identity", "list", "-n", "host", "-q").strip()
    invitation = cli.run("pfa", "-c", "config.json", "identity", "invite", "--manual", "-i", host_id).strip()
    cli_support.accept_and_login(cli, "host.json", invitation, "host")

    cli.run(
        "pf", "-c", "host.json", "openssh", "sign-host",
        f"--public-key={keys}/ssh_host_rsa_key.pub",
        f"--public-key={keys}/ssh_host_ecdsa_key.pub",
        f"--public-key={keys}/ssh_host_ed25519_key.pub",
    )  # fmt: skip
    trusted = cli.run("pf", "-c", "host.json", "openssh", "user-trusted-keys")
    # newline="\n": sshd parses this file, and Python would otherwise write
    # CRLF on Windows and corrupt the key blob.
    with open(f"{keys}/user-ca.pub", "w", newline="\n") as f:
        f.write(trusted)
    cli.run("podman", "exec", sshd.container_id, "pkill", "-HUP", "sshd")

    cli.run("pfa", "-c", "config.json", "identity", "create", "-n", "user")
    user_id = cli.run("pfa", "-c", "config.json", "identity", "list", "-n", "user", "-q").strip()
    cli.run("pfa", "-c", "config.json", "role", "member", "-i", role_id, "-a", "user")
    invitation = cli.run("pfa", "-c", "config.json", "identity", "invite", "--manual", "-i", user_id).strip()
    cli_support.accept_and_login(cli, "user.json", invitation, "user")

    ssh_options = [
        "-o", f"Hostname={sshd.host_address}",
        "-o", "HostKeyAlias=host",
        "-p", str(sshd.host_port),
    ]  # fmt: skip

    # `root` coming back is the whole Windows chain in one line: the certificate
    # is minted, a connection-key oracle is spawned on a named pipe,
    # SSH_AUTH_SOCK points at it, ssh.exe is resolved from System32 rather than
    # Git bash's MSYS build, ssh.exe reaches the oracle over the pipe, and the
    # container's AuthorizedPrincipalsCommand accepts what it signs.
    assert cli.run("pf", "-c", "user.json", "ssh", "-n", *ssh_options, "root@host", "whoami").strip() == "root"

    # An unauthorized username fails fast rather than hanging. Worth its own
    # case: the failure path is where a spawn-and-wait port is most likely to
    # deadlock, and the exit code has to survive being carried back out of
    # run_ssh().
    returncode, _ = cli.status("pf", "-c", "user.json", "ssh", "-n", *ssh_options, "bob@host", "whoami")
    assert returncode == 2

    # Port forwarding, which needs ssh to keep the oracle usable past
    # authentication.
    forwarded = cli.run(
        "pf", "-c", "user.json", "ssh", "-L", "19911:localhost:22", "-n", *ssh_options, "root@host", "echo ok"
    )
    assert forwarded.strip() == "ok"

    # The session-key oracle serves the CLI itself, over a different pipe than
    # the connection oracle above -- a plain API call after all of that confirms
    # `pf login`'s oracle survived the ssh runs.
    hosts = cli.run("pf", "-c", "user.json", "hosts")
    assert "host" in hosts
    assert "shell" in hosts
    assert "port" in hosts
