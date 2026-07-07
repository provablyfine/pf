import copy
import dataclasses
import json
import logging
import os
import os.path
import pathlib
import platform
import random
import re
import shutil
import signal
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import typing

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


def _run(args, log_dir):
    logger.info(f"RUN: {' '.join(args)}")
    stdout_fd, stdout = tempfile.mkstemp(dir=log_dir)
    stderr_fd, stderr = tempfile.mkstemp(dir=log_dir)
    popen = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd)
    if popen.returncode != 0:
        raise Error(
            f'Unable to run returncode={popen.returncode}, stdout={stdout} stderr={stderr} args="{" ".join(args)}"'
        )
    with open(stdout) as f:
        return f.read()


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
def sshd_image(tmp_path_factory):
    """Build SSH server container image once per worker session."""
    sshd_config = """\
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

LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 10
MaxSessions 10

AuthorizedPrincipalsCommand /usr/bin/pf \
    openssh \
    auth-principals \
    --host-certificate=/etc/ssh/keys/ssh_host_ed25519_key.cert \
    --username=%u \
    --certificate=%k
AuthorizedPrincipalsCommandUser nobody

PubkeyAuthentication yes
AuthorizedKeysFile none
HostbasedAuthentication no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

Subsystem sftp /usr/libexec/openssh/sftp-server
TrustedUserCAKeys /etc/ssh/keys/user-ca.pub
"""
    start_sh = """\
ssh-keygen -t ed25519 -f /etc/ssh/keys/ssh_host_ed25519_key -N "" > /dev/null
ssh-keygen -t ecdsa -f /etc/ssh/keys/ssh_host_ecdsa_key -N "" > /dev/null
ssh-keygen -t rsa -f /etc/ssh/keys/ssh_host_rsa_key -N "" > /dev/null
/usr/sbin/sshd -D -e
"""
    containerfile = f"""\
FROM alpine:3.23

RUN apk add --no-cache openssh-server openssh-keygen python3 uv

COPY packages/provablyfine-client /tmp/pfc/
RUN --mount=type=cache,target=/root/.cache/uv uv pip install \\
    --quiet --link-mode=copy --system --break-system-packages /tmp/pfc && \\
    rm -rf /tmp/pfc

COPY pyproject.toml README.md LICENSE.md hatch_build.py /tmp/pf/
COPY src /tmp/pf/src/
RUN --mount=type=cache,target=/root/.cache/uv HATCH_TARGET_ARCH=unsupported uv pip install \\
    --quiet --link-mode=copy --system --break-system-packages --no-sources /tmp/pf && \\
    rm -rf /tmp/pf

RUN mkdir -p /run/sshd && \\
    adduser -D alice && \\
    adduser -D bob && \\
    adduser -D charlie

# unlock accounts
RUN passwd -u alice && \\
    passwd -u bob && \\
    passwd -u charlie

RUN printf '%b' '{sshd_config.replace("\n", "\\n")}' > /etc/ssh/sshd_config

EXPOSE 22

RUN printf '%b' '{start_sh.replace("\n", "\\n")}' > /run/start.sh

CMD ["/bin/sh", "/run/start.sh"]
    """
    tmp_path = tmp_path_factory.getbasetemp().parent
    with tempfile.NamedTemporaryFile(mode="w+", dir=tmp_path, delete=False) as container_file:
        container_file.write(containerfile)
        container_file.flush()

        stdout = _run(["podman", "build", "--quiet", "--file", container_file.name, tld()], tmp_path)
        image_id = stdout.strip("\n")
        if "\n" in image_id:
            assert False, image_id
    return image_id


@pytest.fixture
def sshd(request, sshd_image, tmp_path):
    with tempfile.TemporaryDirectory(dir=tld()) as ssh_keys_directory:
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
            ],
            tmp_path,
        )
        container_id = stdout.strip("\n")
        stdout = _run(["podman", "port", container_id], tmp_path)
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
            _run(["podman", "container", "stop", "-t", "0", container_id], tmp_path)


@dataclasses.dataclass(frozen=True)
class SshAgent:
    socket: str


@pytest.fixture
def ssh_agent(request):
    if not shutil.which("ssh-agent"):
        pytest.skip("ssh-agent not found")
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
def api(request, tmp_path):
    tmp_path = tmp_path.absolute()
    api_kek_file = tmp_path / "kek_file.key"
    api_config = tmp_path / "config.json"
    api_port_file = tmp_path / "api.port"
    api_log = tmp_path / "api.log"
    with open(api_kek_file, "wb+") as f:
        f.write(random.randbytes(32))
    with open(api_config, "w+") as f:
        f.write(
            json.dumps(
                {
                    "tenant_registry_url": f"sqlite:///{tmp_path / 'tenants.db'!s}",
                    "tenants_dir": str(tmp_path),
                    "debug": True,
                    "log_level": 3,
                    "kek_filename": str(api_kek_file),
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
        print("\n=== API Server Startup Failed ===")
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


_FRPC_VERSION = "0.69.1"

_FRPC_SHA256: dict[str, str] = {
    "linux-amd64": "7be257b72dbbc60bcb3e0e25a5afd1dfac7b63f897084864d3c956dd3d5674e1",
    "linux-arm64": "bbc0c75e896af3f292fb46ba09c844a04fa9b5ea3530c039c7af20637f836355",
    "darwin-amd64": "2bc26d02100ef333f2712149ea5997dc530dc0eefac64f4be41cb0f49d032f40",
    "darwin-arm64": "310012e2f1dcf3cdde2605d29b95340b686c94d1680a23711d58efeffc02f64e",
}


def _find_frps(tmp_path: pathlib.Path) -> str:
    frps_in_path = shutil.which("frps")
    if frps_in_path:
        return frps_in_path

    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "darwin": "darwin"}.get(system, system)
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    target = f"{os_name}-{arch}"

    if target not in _FRPC_SHA256:
        pytest.skip(f"frps not available for platform {target!r}")

    tarball_name = f"frp_{_FRPC_VERSION}_{os_name}_{arch}.tar.gz"
    tarball_path = pathlib.Path(tld()) / ".cache" / tarball_name

    if not tarball_path.exists():
        pytest.skip(f"frps tarball not found at {tarball_path}; run 'uv build' first to download it")

    frps_path = tmp_path / "frps"
    with tarfile.open(tarball_path) as tf:
        member = tf.getmember(f"frp_{_FRPC_VERSION}_{os_name}_{arch}/frps")
        member.name = "frps"
        tf.extract(member, path=tmp_path, filter="data")

    frps_path.chmod(frps_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(frps_path)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclasses.dataclass(frozen=True)
class FrPs:
    bind_port: int
    connect_port: int


@pytest.fixture
def frps(api: Api, tmp_path: pathlib.Path, request: pytest.FixtureRequest) -> typing.Generator[FrPs, None, None]:
    frps_binary = _find_frps(tmp_path)
    bind_port = _free_port()
    connect_port = _free_port()
    frps_log = tmp_path / "frps.log"

    config = {
        "bindPort": bind_port,
        "tcpmuxHTTPConnectPort": connect_port,
        "httpPlugins": [
            {
                "name": "pf-plugin",
                "addr": f"http://127.0.0.1:{api.port}/frps/plugin",
                "ops": ["Login"],
            }
        ],
    }
    config_path = tmp_path / "frps.json"
    with open(config_path, "w") as f:
        json.dump(config, f)

    frps_log_file = open(frps_log, "w+")
    popen = subprocess.Popen(
        [frps_binary, "-c", str(config_path)],
        stdout=frps_log_file,
        stderr=subprocess.STDOUT,
    )

    start = time.time()
    ready = False
    while time.time() - start < 10:
        try:
            with socket.create_connection(("127.0.0.1", bind_port), timeout=0.5):
                ready = True
                break
        except OSError:
            time.sleep(0.1)

    if not ready:
        popen.terminate()
        popen.wait()
        frps_log_file.flush()
        with open(frps_log) as f:
            print(f.read())
        raise Exception("frps failed to start")

    try:
        yield FrPs(bind_port=bind_port, connect_port=connect_port)
    finally:
        popen.terminate()
        popen.wait()
        frps_log_file.close()
        if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
            print(f"frps log: {frps_log}")
