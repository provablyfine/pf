"""Keep `_win32` out of collection off Windows.

It has to live here, in the *parent* directory, rather than inside `_win32`:
a `collect_ignore` there is consulted only after pytest has descended into the
package and imported its `__init__.py`, which reaches `_win32api` and dies at
`ctypes.WinDLL("kernel32")`. Ignoring the directory from outside is what
actually prevents the import. (A `pytest.mark.skipif` in the test modules is
later still -- skipping happens after import.)

`_posix` needs no equivalent: its modules import cleanly on Windows, where
`peercred` dispatches to `_unsupported` and the test modules skip themselves.
"""

from __future__ import annotations

import sys

collect_ignore = [] if sys.platform == "win32" else ["_win32"]
