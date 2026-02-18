import subprocess
import tempfile
import os
import os.path
import copy

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
def test_idb_cram(api, filename):
    run_cram(f'tests/{filename}', {'API_PORT': str(api.port)})


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
    run_cram(f'tests/{filename}', {'SSH_AUTH_SOCK': ssh_agent.socket})
