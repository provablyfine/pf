import subprocess
import time
import tempfile
import random
import os
import os.path
import copy
import signal
import re

import json
import requests
import pytest
import jinja2


def run_cram(filename, env):
    environ = copy.copy(os.environ)
    path = os.path.abspath(os.path.join(os.getcwd(), 'scripts'))
    environ['PATH'] = f"{path}:{environ['PATH']}"
    environ.update(env)
    if filename.endswith('.t.jinja'):
        directory = os.path.dirname(filename)
        # We are careful to create the generated file in the directory that contains the jinja file
        # to make it possible for cram to define a valid TESTDIR variable.
        with tempfile.NamedTemporaryFile(dir=directory, suffix='.t', mode='w+') as tmp, open(filename, 'r') as f:
            data = f.read()
            template = jinja2.Template(data)
            rendered = template.render()
            tmp.write(rendered)
            tmp.flush()
            completed = subprocess.run(['cram', tmp.name], env=environ)
    else:
        completed = subprocess.run(['cram', filename], env=environ)
    assert completed.returncode == 0


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
    
    yield socket

    os.kill(pid, signal.SIGTERM)


@pytest.fixture
def api_port(request):
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

    yield api_port

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


@pytest.mark.parametrize("filename", [
    "idb-tags.t",
    "idb-boundaries.t",
    "idb-roles.t",
    "idb-identity.t",
    "idb-permission.t",
    "idb-access-control-tag.t.jinja",
    "idb-access-control-identity.t.jinja",
    "idb-access-control-identity-invite.t.jinja",
    "idb-access-control-identity-create.t.jinja",
    "idb-access-control-identity-delete.t.jinja",
    "idb-access-control-identity-update.t.jinja",
    "idb-access-control-identity-tag.t.jinja",
    "idb-access-control-identity-read.t.jinja",
])
def test_idb_cram(api_port, filename):
    run_cram(f'tests/{filename}', {'API_PORT': str(api_port)})


@pytest.mark.parametrize("filename", [
    "ssh-certificates.t.jinja",
    "ssh-ecdsa-certificates.t.jinja",
    "ssh-keys.t",
])
def test_ssh_cram(filename):
    run_cram(f'tests/{filename}', {})

@pytest.mark.parametrize("filename", [
    "ssh-agent-keys.t.jinja",
])
def test_ssh_agent_cram(filename, ssh_agent):
    run_cram(f'tests/{filename}', {'SSH_AUTH_SOCK': ssh_agent})
