"""Standalone helper spawned by test_peercred.py to build a real N-deep
subprocess chain. Not a pytest module itself (leading underscore keeps
pytest's default collection from picking it up); invoked as:

    python3 _test_ancestry_helper.py <depth> <pid_file> <ready_file>

At depth 0 (the leaf), writes its own PID to `pid_file`, signals readiness by
creating `ready_file`, then sleeps -- giving the test time to query its
ancestry while it's still alive. At any other depth, re-execs itself one
level shallower and blocks on it, keeping the whole chain alive throughout.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time


def main() -> None:
    depth = int(sys.argv[1])
    pid_file = sys.argv[2]
    ready_file = sys.argv[3]
    if depth == 0:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
        with open(ready_file, "w") as f:
            f.write("ready")
        time.sleep(30)
    else:
        subprocess.run([sys.executable, __file__, str(depth - 1), pid_file, ready_file])  # noqa: S603


if __name__ == "__main__":
    main()
