import os
import tempfile

from . import utils


def test_tmpdir_too_long(api):
    long = os.path.join(tempfile.gettempdir(), "pf-tmpdir-guard-" + "x" * 80)
    os.makedirs(long, exist_ok=True)
    utils.run_cram("tests/oracle-tmpdir-too-long.t", {"API_PORT": str(api.port), "TMPDIR": long})
