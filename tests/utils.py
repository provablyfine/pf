import tempfile
import os
import os.path
import copy
import subprocess

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
