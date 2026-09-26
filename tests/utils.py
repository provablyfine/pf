import json
import os
import os.path
import pathlib
import shutil
import subprocess
import sys
import tempfile
import typing

import jinja2
import pytest
import sqlalchemy

import provablyfine.api.db
import provablyfine.api.registry_db

if typing.TYPE_CHECKING:
    import tests.conftest


def root_tenant_db_path(api: "tests.conftest.Api") -> pathlib.Path:
    """The root tenant's sqlite file, derived the way the server does it.

    For tests that need to open it directly (e.g. to hold a competing transaction),
    rather than hardcoding a filename the server's own naming convention might change.
    """
    config = json.loads((api.log.parent / "config.json").read_text())
    url = provablyfine.api.db.derive_tenant_url(
        config["tenant_registry_url"], provablyfine.api.registry_db.ROOT_TENANT_UUID
    )
    path = sqlalchemy.make_url(url).database
    assert path is not None
    return pathlib.Path(path)


def run_cram(filename: str, env: dict[str, str]) -> None:
    """Run a cram `.t` script."""
    if sys.platform == "win32":
        pytest.skip("cram is posix only. Not supported on Windows; Windows coverage uses tests/cli.py")
    # See https://github.com/provablyfine/pf/issues/117
    environ = dict(os.environ)
    path = os.path.abspath(os.path.join(os.getcwd(), "scripts"))
    environ["PATH"] = f"{path}{os.pathsep}{environ['PATH']}"
    our_tmp = tempfile.mkdtemp(prefix="pf-cram-", dir="/tmp")
    for var in ("TMPDIR", "TEMP", "TMP"):
        environ[var] = our_tmp
    environ.update(env)
    try:
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
    finally:
        shutil.rmtree(our_tmp, ignore_errors=True)


def _run_cram_command(filename: str, environ: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["uv", "run", "cram", "--shell", "/bin/bash", "--keep-tmpdir", filename],
        env=environ,
        start_new_session=True,
    )
