import pathlib
import shutil
import sys

import pytest

from . import utils


@pytest.mark.skipif(sys.platform == "win32", reason="cram is posix only")
@pytest.mark.skipif(not shutil.which("uv"), reason="uv not found")
def test_login_under_uv_run(api):
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    utils.run_cram("tests/login-uv.t", {"API_PORT": str(api.port), "REPO_ROOT": str(repo_root)})
