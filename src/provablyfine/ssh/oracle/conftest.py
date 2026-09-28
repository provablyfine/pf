from __future__ import annotations

import sys

collect_ignore = ["_posix"] if sys.platform == "win32" else ["_win32"]
