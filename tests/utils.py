import copy
import os
import os.path
import subprocess
import sys
import tempfile

import jinja2
import pytest


def run_cram(filename: str, env: dict[str, str]):
    """Run a cram `.t` script."""
    if sys.platform == "win32":
        pytest.skip("cram is posix only. Not supported on Windows; Windows coverage uses tests/cli.py")
    environ = copy.copy(os.environ)
    path = os.path.abspath(os.path.join(os.getcwd(), "scripts"))
    environ["PATH"] = f"{path}{os.pathsep}{environ['PATH']}"
    environ.update(env)
    if filename.endswith(".t.jinja"):
        directory = os.path.dirname(filename)
        # We are careful to create the generated file in the directory that contains the jinja file
        # to make it possible for cram to define a valid TESTDIR variable.
        with tempfile.NamedTemporaryFile(dir=directory, suffix=".t", mode="w+") as tmp, open(filename) as f:
            data = f.read()
            template = jinja2.Template(data)
            rendered = template.render()
            tmp.write(rendered)
            tmp.flush()
            completed = _run_cram_command(tmp.name, environ)
    else:
        completed = _run_cram_command(filename, environ)
    assert completed.returncode == 0


def _run_cram_command(filename: str, environ: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["uv", "run", "cram", "--shell", "/bin/bash", filename],
        env=environ,
        start_new_session=True,
    )
