import copy
import dataclasses
import json
import logging
import os
import os.path
import random
import re
import signal
import shutil
import socket
import subprocess
import tempfile
import time
import typing

import filelock
import psutil
import pytest
import requests

logger = logging.getLogger(__name__)

pytest_plugins = ["tests.mock_oidc"]


class Error(BaseException):
    pass


def pytest_xdist_auto_num_workers(config):
    # This only runs if '-n auto' is used
    physical_cores = psutil.cpu_count(logical=False)
    # The number of physical cores is a better number than the number
    # of logical cores to run tests.
    return physical_cores or 1  # Fallback to 1 if detection fails


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


@pytest.fixture(scope="session")
def sshd_image(tmp_path_factory, worker_id):
    # pattern borrowed from pytest manual
    if worker_id == "master":
        return _build_image()
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    fn = root_tmp_dir / "sshd-image.json"
    with filelock.FileLock(str(fn) + ".lock"):
        if fn.is_file():
            data = json.loads(fn.read_text())
        else:
            data = _build_image()
            fn.write_text(json.dumps(data))
    return data


def _build_image():
    """Build SSH server container image once per worker session."""
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
    with tempfile.NamedTemporaryFile(mode="w+") as container_file:
        container_file.write(containerfile)
        container_file.flush()

        stdout = _run(["podman", "build", "--quiet", "--file", container_file.name, tld()])
        image_id = stdout.strip("\n")
        if "\n" in image_id:
            assert False, image_id
    return image_id


def _build_bastion_image() -> str:
    pf_bastion_control_socket = """[Unit]
Description=PF Bastion Control Socket

[Socket]
ListenStream=/run/pf/bastion-control.sock
SocketMode=0666
FileDescriptorName=pf-bastion-control
Service=pf-bastion.service

[Install]
WantedBy=sockets.target
"""
    pf_bastion_socket = """[Unit]
Description=PF Bastion Socket

[Socket]
ListenStream=/run/pf/bastion.sock
SocketMode=0666
FileDescriptorName=pf-bastion-main
Service=pf-bastion.service

[Install]
WantedBy=sockets.target pf-bastion-control.socket
"""

    pf_bastion_service = """[Unit]
Description=PF Bastion
After=network.target

[Service]
Type=notify
NotifyAccess=all
PassEnvironment=ISSUER_PREFIX
WorkingDirectory=/run/pf
ExecStart=/usr/bin/python -m coverage run --source=/usr/local/lib/python3.14/site-packages/pf -p /usr/local/bin/pf-bastion -ddd --log-filename=/run/pf/pf-bastion.${INVOCATION_ID}.log --issuer-prefix "${ISSUER_PREFIX}" --port-file /run/pf/bastion.port --domain-suffix localhost --control-socket /run/pf/bastion-control.sock
FileDescriptorStoreMax=128
"""

    containerfile = f"""FROM fedora:latest
RUN dnf install -y python3 uv systemd python3-coverage && dnf clean all
RUN systemctl mask systemd-resolved systemd-oomd

COPY . /tmp/pf/
RUN uv pip install --system --break-system-packages /tmp/pf

RUN mkdir -p /etc/systemd/system

RUN cat <<'EOF' > /etc/systemd/system/pf-bastion-control.socket
{pf_bastion_control_socket}
EOF

RUN cat <<'EOF' > /etc/systemd/system/pf-bastion.socket
{pf_bastion_socket}
EOF

RUN cat <<'EOF' > /etc/systemd/system/pf-bastion.service
{pf_bastion_service}
EOF

RUN systemctl enable pf-bastion.socket pf-bastion-control.socket

CMD ["/sbin/init"]
"""

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".Containerfile") as container_file:
        container_file.write(containerfile)
        container_file.flush()

        stdout = _run(["podman", "build", "--quiet", "--file", container_file.name, tld()])
        image_id = stdout.strip("\n")
        if "\n" in image_id:
            assert False, image_id
    return image_id


@pytest.fixture
def sshd(request, sshd_image):
    with tempfile.TemporaryDirectory() as ssh_keys_directory:
        # Make sure "nobody" can read this directory
        fd = os.open(ssh_keys_directory, 0)
        os.chmod(fd, 0o755)
        os.close(fd)

        stdout = _run(
            [
                "podman",
                "run",
                "--detach",  # run in background and return immediately
                "--quiet",
                "--publish-all",
                "--volume",
                f"{ssh_keys_directory}:/etc/ssh/keys:rw",
                sshd_image,
            ]
        )
        container_id = stdout.strip("\n")
        stdout = _run(["podman", "port", container_id])
        try:
            port = _parse_port_mapping(stdout)
        except Exception:
            print(f"SSH Server container: {container_id}")
            raise
        # Wait for sshd to be ready inside container (key generation + daemon startup can take ~10s)
        start = time.time()
        while time.time() - start < 30:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            print(f"SSH Server container: {container_id}")
            raise Exception(f"sshd not ready after 30s in container {container_id}")
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

    pf_start_timeout = 10
    start = time.time()
    api_port = None
    api_ready = False
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
        api_ready = True
        break
    if not api_ready:
        api_log_file.flush()
        with open(api_log) as f:
            log_content = f.read()
        print(f"\n=== API Server Startup Failed ===")
        print(f"Config: {api_config}")
        print(f"Port file: {api_port_file}")
        print(f"Log:\n{log_content}")
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
    control_socket: str


def _start_bastion_process(
    api_port: int,
    port_file: str,
    log_file: str,
    control_socket: str,
    port: int = 0,
    env: dict | None = None,
    pass_fds: tuple = (),
    preexec_fn=None,
) -> tuple[subprocess.Popen, typing.IO]:
    """Helper to start a bastion process. Returns (popen, log_file_handle)."""
    if env is None:
        env = copy.copy(os.environ)

    log_f = open(log_file, "a" if os.path.exists(log_file) else "w")
    issuer_prefix = f"http://127.0.0.1:{api_port}/pf/t"
    args = [
        "scripts/pf-bastion",
        "--issuer-prefix",
        issuer_prefix,
        "--port-file",
        port_file,
        "--domain-suffix",
        "localhost",
        "--control-socket",
        control_socket,
    ]
    if port > 0:
        args.extend(["-p", str(port)])

    popen = subprocess.Popen(
        args,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        pass_fds=pass_fds,
        preexec_fn=preexec_fn,
    )
    return popen, log_f


@pytest.fixture
def bastion_server(request, api):
    tmp_dir = tempfile.TemporaryDirectory()
    port_file = os.path.join(tmp_dir.name, "bastion.port")
    log_file = os.path.join(tmp_dir.name, "bastion.log")
    control_socket = os.path.join(tmp_dir.name, "pf-bastion-control.sock")

    popen, log_f = _start_bastion_process(api.port, port_file, log_file, control_socket)

    start = time.time()
    port = None
    bastion_ready = False
    while time.time() - start < 10:
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
        # Verify bastion is actually accepting TCP connections
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                bastion_ready = True
                break
        except OSError:
            time.sleep(0.1)
            continue

    if not bastion_ready:
        log_f.flush()
        with open(log_file) as f:
            print(f"Bastion log: {f.read()}")
        raise Exception("Unable to start bastion server")

    yield BastionServer(port=port, control_socket=control_socket)

    popen.terminate()
    log_f.close()
    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            with open(log_file) as f:
                print(f"Bastion log:\n{f.read()}")
            return
    tmp_dir.cleanup()


@dataclasses.dataclass(frozen=True)
class BastionContainer:
    """Bastion server running in podman under real systemd."""

    main_socket: str
    control_socket: str
    container_id: str


@pytest.fixture
def bastion_container(request, api, tmp_path):
    """Start bastion under real systemd in a podman container."""
    bastion_image = _build_bastion_image()

    # Create shared directories
    shared_dir = tmp_path / "run-pf"
    shared_dir.mkdir()
    logs_dir = tmp_path / "journal"
    logs_dir.mkdir()

    # Run bastion container with port forwarding

    command = [
        "podman",
        "run",
        "--detach",
        "--systemd=always",
        "--network=host",
        "--volume",
        f"{shared_dir}:/run/pf:rw",
        "--volume",
        f"{logs_dir}:/var/log/journal:rw",
        "--env",
        f"ISSUER_PREFIX=http://127.0.0.1:{api.port}/pf/t",
        bastion_image,
    ]
    container_id = subprocess.check_output(command).decode().strip()


    control_socket = str(shared_dir / "bastion-control.sock")
    main_socket = str(shared_dir / "bastion.sock")

    print(f"main={main_socket} control={control_socket}")
    yield BastionContainer(main_socket=main_socket, control_socket=control_socket, container_id=container_id)

    subprocess.run(["podman", "stop", "-t", "5", container_id])

    filenames = [filename for filename in os.listdir(shared_dir) if filename.startswith(".coverage")]
    for filename in filenames:
        shutil.copy(os.path.join(shared_dir, filename), filename)

    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            print(f"Bastion container ID: {container_id}")
            print(f"Systemd journal logs: {logs_dir}")
            print(f"Control socket and port file: {shared_dir}")

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
