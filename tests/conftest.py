import copy
import dataclasses
import json
import logging
import os
import os.path
import random
import re
import signal
import subprocess
import tempfile
import time

import pytest
import requests

logger = logging.getLogger(__name__)


class Error(BaseException):
    pass


def tld():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run(args):
    logger.info(f"RUN: {' '.join(args)}")
    popen = subprocess.run(args, capture_output=True, text=True)
    if popen.returncode != 0:
        with tempfile.NamedTemporaryFile(delete=False, delete_on_close=False, mode="w+") as f:
            f.write(popen.stdout)
            f.flush()
            raise Error(f'Unable to run returncode={popen.returncode}, stdout={f.name}. args="{" ".join(args)}"')
    return popen.stdout


def _parse_port_mapping(s):
    items = s.split("->")
    if len(items) != 2:
        raise Error(f"Invalid port mapping: {s}")
    _container, host = items
    items = host.split(":")
    if len(items) != 2:
        raise Error(f"Invalid host address: {host}")
    _hostname, port = items
    port = port.strip()
    if not port.isdigit():
        raise Error(f"Invalid port number: {port}")
    return int(port)


@dataclasses.dataclass(frozen=True)
class SshD:
    host_port: int
    keys_directory: str
    container_id: str


@pytest.fixture
def sshd(request):
    containerfile = """
FROM alpine:3.23

RUN apk add --no-cache openssh-server openssh-keygen python3 uv

COPY pyproject.toml /tmp/pf/
COPY src /tmp/pf/src/
RUN --mount=type=cache,target=/root/.cache/uv uv pip install \
    --quiet --link-mode=copy --system --break-system-packages /tmp/pf && \
    rm -rf /tmp/pf

RUN mkdir -p /run/sshd && \
    adduser -D alice && \
    adduser -D bob && \
    adduser -D charlie

# unlock accounts
RUN passwd -u alice && \
    passwd -u bob && \
    passwd -u charlie

RUN cat <<EOF >/etc/ssh/sshd_config
Port 22
ListenAddress 0.0.0.0
AddressFamily any
ListenAddress ::

HostKey /etc/ssh/keys/ssh_host_rsa_key
HostKey /etc/ssh/keys/ssh_host_ecdsa_key
HostKey /etc/ssh/keys/ssh_host_ed25519_key
HostCertificate /etc/ssh/keys/ssh_host_rsa_key.cert
HostCertificate /etc/ssh/keys/ssh_host_ecdsa_key.cert
HostCertificate /etc/ssh/keys/ssh_host_ed25519_key.cert

RekeyLimit default none

SyslogFacility AUTH
LogLevel INFO
#LogLevel DEBUG

LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 10
MaxSessions 10

AuthorizedPrincipalsCommand /usr/bin/pf openssh authorized-principals \
        --host-certificate=/etc/ssh/keys/ssh_host_ed25519_key.cert \
        --username=%u --certificate=%k
AuthorizedPrincipalsCommandUser nobody

PubkeyAuthentication yes
AuthorizedKeysFile	none
HostbasedAuthentication no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

Subsystem	sftp	/usr/libexec/openssh/sftp-server
TrustedUserCAKeys /etc/ssh/keys/user-ca.pub
EOF

EXPOSE 22

RUN cat <<EOF > /run/start.sh
ssh-keygen -t ed25519 -f /etc/ssh/keys/ssh_host_ed25519_key -N "" > /dev/null
ssh-keygen -t ecdsa -f /etc/ssh/keys/ssh_host_ecdsa_key -N "" > /dev/null
ssh-keygen -t rsa -f /etc/ssh/keys/ssh_host_rsa_key -N "" > /dev/null
/usr/sbin/sshd -D -e
EOF

CMD ["/bin/sh", "/run/start.sh"]
    """
    with tempfile.NamedTemporaryFile(mode="w+") as container_file, tempfile.TemporaryDirectory() as ssh_keys_directory:
        container_file.write(containerfile)
        container_file.flush()

        # Make sure "nobody" can read this directory
        fd = os.open(ssh_keys_directory, 0)
        os.chmod(fd, 0o755)
        os.close(fd)

        stdout = _run(["podman", "build", "--quiet", "--file", container_file.name, tld()])
        image_id = stdout.strip("\n")
        if "\n" in image_id:
            assert False, image_id
        stdout = _run(
            [
                "podman",
                "run",
                "--detach",  # run in background and return immediately
                "--quiet",
                "--publish-all",
                "--volume",
                f"{ssh_keys_directory}:/etc/ssh/keys:rw",
                image_id,
            ]
        )
        container_id = stdout.strip("\n")
        stdout = _run(["podman", "port", container_id])
        try:
            port = _parse_port_mapping(stdout)
        except Exception:
            print(f"SSH Server container: {container_id}")
            raise
        try:
            yield SshD(host_port=port, keys_directory=ssh_keys_directory, container_id=container_id)
        finally:
            if hasattr(request.node, "rep_call"):
                if request.node.rep_call.failed:
                    print(f"SSH Server container: {container_id}")
            _run(["podman", "container", "stop", "-t", "0", container_id])


@dataclasses.dataclass(frozen=True)
class SshAgent:
    socket: str


@pytest.fixture
def ssh_agent(request):
    completed = subprocess.run(["ssh-agent", "-s"], capture_output=True)
    assert completed.returncode == 0
    pid = None
    socket = None
    for line in completed.stdout.split(b"\n"):
        line = line.decode("ascii")
        m = re.search("SSH_AUTH_SOCK=([^;]+)", line)
        if m is not None:
            socket = m.group(1)
            continue
        m = re.search("Agent pid ([0-9]+);", line)
        if m is not None:
            pid = int(m.group(1))
            continue
    assert pid is not None and socket is not None

    yield SshAgent(socket)

    os.kill(pid, signal.SIGTERM)


@dataclasses.dataclass(frozen=True)
class Api:
    port: int


@pytest.fixture
def api(request):
    tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True, delete=False)
    api_kek_file = os.path.join(tmp_dir.name, "kek_file.key")
    api_config = os.path.join(tmp_dir.name, "config.json")
    api_port_file = os.path.join(tmp_dir.name, "api.port")
    api_log = os.path.join(tmp_dir.name, "api.log")
    with open(api_kek_file, "wb+") as f:
        f.write(random.randbytes(32))
    with open(api_config, "w+") as f:
        f.write(
            json.dumps(
                {
                    "tenant_registry_url": f"sqlite:///{os.path.join(tmp_dir.name, 'tenants.db')}",
                    "tenants_dir": tmp_dir.name,
                    "debug": True,
                    "log_level": "DEBUG",
                    "kek_filename": api_kek_file,
                    #'debug_sql': True,
                }
            )
        )
    env = copy.copy(os.environ)
    api_log_file = open(api_log, "w+")
    popen = subprocess.Popen(
        ["scripts/pf-server", "-c", api_config, "--port-file", api_port_file],
        stdout=api_log_file,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    pf_start_timeout = 5
    start = time.time()
    api_port = None
    while time.time() - start < pf_start_timeout:
        try:
            with open(api_port_file) as f:
                data = f.read()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        try:
            api_port = int(data)
        except Exception:
            time.sleep(0.1)
            continue
        try:
            response = requests.get(f"http://127.0.0.1:{api_port}/pf/t/root/directory")
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
            continue
        if response.status_code != 200:
            time.sleep(0.1)
            continue
        break
    if api_port is None:
        raise Exception("Unable to start pf server")

    yield Api(api_port)

    # tear down
    popen.terminate()
    popen.wait()
    api_log_file.close()
    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            print(f"API log: {api_log}")
            print(f"API config: {api_config}")
            print(f"API portfile: {api_port_file}")
            print(f"API kek: {api_kek_file}")
            return
    tmp_dir.cleanup()


@dataclasses.dataclass(frozen=True)
class BastionServer:
    port: int


@pytest.fixture
def bastion_server(request, api):
    tmp_dir = tempfile.TemporaryDirectory()
    port_file = os.path.join(tmp_dir.name, "bastion.port")
    log_file = os.path.join(tmp_dir.name, "bastion.log")

    env = copy.copy(os.environ)
    log_f = open(log_file, "w+")
    issuer_prefix = f"http://127.0.0.1:{api.port}/pf/t"
    popen = subprocess.Popen(
        ["scripts/pf-bastion", "--issuer-prefix", issuer_prefix, "--port-file", port_file],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    start = time.time()
    port = None
    while time.time() - start < 5:
        try:
            with open(port_file) as f:
                data = f.read()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        try:
            port = int(data.strip())
        except Exception:
            time.sleep(0.1)
            continue
        break

    if port is None:
        log_f.flush()
        with open(log_file) as f:
            print(f"Bastion log: {f.read()}")
        raise Exception("Unable to start bastion server")

    yield BastionServer(port=port)

    popen.terminate()
    popen.wait()
    log_f.close()
    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            with open(log_file) as f:
                print(f"Bastion log:\n{f.read()}")
            return
    tmp_dir.cleanup()


@pytest.fixture(autouse=True)
def pf_log_directory(tmp_path, request):
    """Set PF_LOG_DIRECTORY to a unique temp directory for each test.

    Logs are auto-deleted after passing tests. On failure, logs are preserved
    and the location is printed. To keep all logs, run with:
      uv run pytest --basetemp=/tmp/pf-test-logs tests/
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    os.environ["PF_LOG_DIRECTORY"] = str(log_dir)

    def check_preserve_logs():
        if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
            print(f"\nTest failed. Logs preserved at: {log_dir}")

    request.addfinalizer(check_preserve_logs)
    return log_dir


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
