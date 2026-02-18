import os.path
import logging
import subprocess
import tempfile
import dataclasses
import re
import random
import copy
import time
import signal

import json
import pytest
import requests


logger = logging.getLogger(__name__)


class Error(BaseException):
    pass


def tld():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def _run(args):
    logger.info(f'RUN: {" ".join(args)}')
    popen = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if popen.returncode != 0:
        with tempfile.NamedTemporaryFile(delete=False, delete_on_close=False, mode='w+') as f:
            f.write(popen.stdout)
            f.flush()
            raise Error(f'Unable to run returncode={popen.returncode}, stdout={f.name}. args=\"{" ".join(args)}\"')
    return popen.stdout


def _parse_port_mapping(s):
    items = s.split('->')
    if len(items) != 2:
        raise Error(f'Invalid port mapping: {s}')
    container, host = items
    items = host.split(':')
    if len(items) != 2:
        raise Error(f'Invalid host address: {host}')
    hostname, port = items
    port = port.strip()
    if not port.isdigit():
        raise Error(f'Invalid port number: {port}')
    return int(port)

@dataclasses.dataclass(frozen=True)
class SshD:
    host_port: int
    user_ca_public_keys_filename: str


@pytest.fixture
def sshd():
    containerfile = """
FROM alpine:3.23

RUN apk add --no-cache openssh-server openssh-keygen python3 uv

COPY pyproject.toml /tmp/idb/
COPY src /tmp/idb/src/
RUN --mount=type=cache,target=/root/.cache/uv uv pip install --quiet --link-mode=copy --system --break-system-packages /tmp/idb && \
    rm -rf /tmp/idb

RUN ssh-keygen -A && \
    mkdir -p /run/sshd && \
    adduser -D alice && \
    adduser -D bob && \
    adduser -D charlie

RUN cat <<EOF >/etc/ssh/sshd_config
Port 22
ListenAddress 0.0.0.0
AddressFamily any
ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

RekeyLimit default none

SyslogFacility AUTH
LogLevel INFO

LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 10
MaxSessions 10

AuthorizedPrincipalsCommand /usr/bin/idbctl openssh authorized-principals --certificate=%K --username=%u
AuthorizedPrincipalsCommandUser nobody

PubkeyAuthentication yes
AuthorizedKeysFile	none
HostbasedAuthentication no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

Subsystem	sftp	/usr/libexec/openssh/sftp-server
TrustedUserCAKeys /etc/ssh/user-ca.pub
EOF

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
    """
    with tempfile.NamedTemporaryFile(mode='w+') as container_file, \
            tempfile.NamedTemporaryFile(mode='w+') as user_ca_public_keys:
        container_file.write(containerfile)
        container_file.flush()

        stdout = _run(['podman', 'build', '--quiet', '--file', container_file.name, tld()])
        image_id = stdout.strip('\n')
        if '\n' in image_id:
            assert False, image_id
        stdout = _run([
            'podman',
            'run',
            '--detach', # run in background and return immediately
            '--quiet',
            '--publish-all',
            '--volume',
            f'{user_ca_public_keys.name}:/etc/ssh/user-ca.pub:ro',
            image_id,
        ])
        container_id = stdout.strip('\n')
        stdout = _run(['podman', 'port', container_id])
        port = _parse_port_mapping(stdout)

        try:
            yield SshD(port, user_ca_public_keys.name)
        finally:
            logs = _run(['podman', 'logs', container_id])
            print(logs)
            _run(['podman', 'stop', container_id])


@dataclasses.dataclass(frozen=True)
class SshAgent:
    socket: str


@pytest.fixture
def ssh_agent(request):
    completed = subprocess.run(['ssh-agent', '-s'], capture_output=True)
    assert completed.returncode == 0
    pid = None
    socket = None
    for line in completed.stdout.split(b'\n'):
        line = line.decode('ascii')
        m = re.search('SSH_AUTH_SOCK=([^;]+)', line)
        if m is not None:
            socket = m.group(1)
            continue
        m = re.search('Agent pid ([0-9]+);', line)
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
    api_db = os.path.join(tmp_dir.name, 'api.db')
    api_kek_file = os.path.join(tmp_dir.name, 'kek_file.key')
    api_config = os.path.join(tmp_dir.name, 'config.json')
    api_port_file = os.path.join(tmp_dir.name, 'api.port')
    api_log = os.path.join(tmp_dir.name, 'api.log')
    with open(api_kek_file, 'wb+') as f:
        f.write(random.randbytes(32))
    with open(api_config, 'w+') as f:
        f.write(json.dumps({
            'database_url': f'sqlite:///{api_db}',
            'debug': True,
            'log_level': 'DEBUG',
            'kek_filename': api_kek_file,
            #debug_sql: true
        }))
    env = copy.copy(os.environ)
    env['PYTHONUNBUFFERED'] = '1'
    popen = subprocess.Popen(['scripts/idb', '-c', api_config, '--port-file', api_port_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)

    idb_start_timeout = 5
    start = time.time()
    api_port = None
    while time.time() - start < idb_start_timeout:
        try:
            with open(api_port_file) as f:
                data = f.read()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        try:
            api_port = int(data)
        except:
            time.sleep(0.1)
            continue
        try:
            response = requests.get(f'http://127.0.0.1:{api_port}/idb/directory')
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
            continue
        if response.status_code != 200:
            time.sleep(0.1)
            continue
        break
    if api_port is None:
        raise Exception('Unable to start idb server')

    yield Api(api_port)

    # tear down
    popen.terminate()
    stdout, stderr = popen.communicate()
    if hasattr(request.node, 'rep_call'):
        if request.node.rep_call.failed:
            print(f'API log: {api_log}')
            print(f'API db: {api_db}')
            print(f'API config: {api_config}')
            print(f'API portfile: {api_port_file}')
            print(f'API kek: {api_kek_file}')
            with open(api_log, 'w+') as f:
                f.write(stdout)
            return
    tmp_dir.cleanup()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
