# Native Windows installer for `pf` + automated post-install smoke test

## Context

The e2e suite already passes under WSL on Win11, but that's not a native Windows
distribution — it still depends on a Linux userspace. The goal is to ship `pf` (the
end-user CLI) as a real native Windows executable/installer, built and smoke-tested
automatically in CI, so a Windows user can install it and run `pf ssh` without WSL.
Inno Setup was chosen (over WiX/MSI) for the installer wrapper: simpler to script from
CI, and its silent-install flags make automated post-install testing straightforward.

Scope for this pass: **`pf.exe` only** (the CLI in `src/pf/cli/pf`, entry point
`provablyfine.cli.pf.main:pf`). `pfa`/`pfat` are admin-facing tools and can reuse the
exact same PyInstaller/Inno mechanism later — not included here to keep the first PR
reviewable.

## Revised understanding: the agent transport, not AF_UNIX, is the real prerequisite

Earlier planning assumed `src/provablyfine/ssh/agent.py`'s hardcoded `socket.AF_UNIX`
might just work against Win32-OpenSSH's `ssh-agent.exe -a <path>`, and scoped a spike
to confirm that (`packaging/windows/spike_agent_check.py`, committed on `ml/issue-51`,
not yet run). Two things came out of discussion that change the plan materially:

1. **Named pipes are the broader, more native transport.** Windows' built-in OpenSSH
   `ssh-agent` service listens on the well-known named pipe
   `\\.\pipe\openssh-ssh-agent`. Named pipes have no meaningful OS-version floor
   (unlike AF_UNIX, which needs Windows 10 1803+/Server 2019+ kernel support), and
   Python's stdlib `multiprocessing.connection` already speaks Windows named pipes
   with **no extra dependency** (`Client()`/`Listener()` switch to pipes automatically
   on `win32`). AF_UNIX still matters as a fallback (WSL-forwarded agents, Git
   Bash/MSYS `ssh-agent` use real Unix sockets), but named pipe should be the primary
   path, not something we hope AF_UNIX happens to cover.

2. **A pf-owned ephemeral agent (spawn-our-own-`ssh-agent.exe`-per-invocation) was
   considered and rejected.** It would need to be admin-free and self-contained,
   avoiding the Windows agent service's disabled-by-default state — but it directly
   conflicts with how session auth already works: `src/provablyfine/cli/login.py`
   (`ensure_session`, `http_sig_login`, `oidc_login`, lines ~105-179) stores only the
   session key's **fingerprint** in the config file and expects the private key
   material to live in one ambient, persistent agent spanning the whole login session
   — every subsequent `pf` command looks it up by fingerprint. The code's own fallback
   for "no agent available" is to store the session key **as cleartext in the config
   file** (`login.py:167`) — clearly the deliberately-worse option. A private
   per-invocation agent would exit (and take the key with it) the moment each `pf`
   process exits, forcing every Windows user onto that cleartext-fallback path. This
   also matches how `pf ssh`'s own ephemeral per-connection key already behaves
   (`ssh_cli.py`: generated in-process, added to whatever agent already exists, never
   written to disk) — the whole design assumes an ambient agent, not one pf manages
   itself.

   Windows' OpenSSH Authentication Agent service is real but **ships disabled by
   default**, even on Windows 11 — `Get-Service ssh-agent` shows `StartupType:
   Disabled` out of the box. The fix (`Set-Service ssh-agent -StartupType Automatic;
   Start-Service ssh-agent`) is a one-time, admin-required step outside pf's control.
   So instead of working around it with a private agent, `pf` should detect that the
   pipe isn't there and print that exact fix.

Net effect on scope: this is no longer "confirm AF_UNIX works, then package." It's
"add a named-pipe transport (with AF_UNIX fallback) to `ssh.agent.Client`, detect and
guide the user through enabling the Windows agent service when neither is present,
then package." Pageant (PuTTY's agent, a different `WM_COPYDATA`-based protocol, not a
pipe or socket) stays explicitly out of scope for v1.

## Deliverables

### 1. Windows agent transport (`src/provablyfine/ssh/agent.py`)
- `Client.__init__` gains a Windows-specific connection path: on `win32`, try (in
  order) `SSH_AUTH_SOCK` as a named pipe path if set, else the well-known
  `\\.\pipe\openssh-ssh-agent`, via `multiprocessing.connection.Client` (stdlib, no
  new dependency); fall back to the existing AF_UNIX path when `SSH_AUTH_SOCK` points
  at a real Unix socket instead (covers WSL-forwarded agents, Git Bash/MSYS
  `ssh-agent`). POSIX behavior is unchanged.
- The read/write framing (`_send_request`/`_recv_bytes`/`_recv_message`) stays
  transport-agnostic — only the connection step differs, so `PipeConnection`'s
  `send_bytes`/`recv_bytes` need a thin adapter to the raw-byte read/write this class
  already does, or the class holds a small internal "transport" object with
  `send`/`recv` methods that either wraps a raw socket (POSIX/AF_UNIX) or a
  `PipeConnection` (Windows named pipe).
- When neither transport is reachable on Windows, raise a clear, actionable error
  naming the exact `Set-Service`/`Start-Service ssh-agent` fix, surfaced through
  `pfc.exceptions.UI` at the call sites in `login.py`/`ssh_cli.py` rather than a raw
  connection error.
- Repurpose the already-committed spike (`packaging/windows/spike_agent_check.py`,
  `windows-agent-spike.yml`, on `ml/issue-51`) to validate this transport directly
  against the real Windows agent service (once started) instead of the
  `ssh-agent -a <path>`-with-AF_UNIX assumption it currently checks.

### 2. PyInstaller build (`packaging/windows/pf.spec`)
- `onedir` build (not `onefile`) of the `pf` console-script entry point — avoids the
  self-extraction startup cost and antivirus false-positive rate that `onefile` builds
  are known for, at the cost of shipping a folder instead of a single file (fine, since
  Inno Setup packages the folder anyway).
- Add `pyinstaller` to a new `[dependency-groups] windows-build` group in
  `pyproject.toml` rather than the shared `dev` group — it's Windows-only tooling that
  Linux/macOS contributors don't need installed.

### 3. Inno Setup script (`packaging/windows/pf.iss`)
- Per-user install under `%LOCALAPPDATA%\Programs\pf` (no admin elevation required),
  adds the install dir to the user `PATH`.
- Version driven from `pyproject.toml` (same `uv version --short` extraction already
  used in `release.yml`'s `validate` job), passed to `iscc` via `/DMyAppVersion=...`.
- Post-install message/README note: if the OpenSSH Authentication Agent service isn't
  running, `pf` will tell you how to enable it (one-time, needs admin) — the installer
  itself stays admin-free and does not try to enable the service silently.
- **Unsigned for v1** — this will trigger a SmartScreen warning on first run. Note this
  explicitly as a known limitation; code-signing is a follow-up once a certificate is
  provisioned, not a blocker for this PR.

### 4. CI wiring
- `release.yml`: new `build-windows` job (pattern-matched to the existing
  `build-wheels`/`build-sdist` jobs) on `windows-latest` — `uv sync`, run PyInstaller,
  run `iscc`, upload `pf-setup.exe` as a release artifact, attached to the GitHub
  Release alongside the wheel/sdist.
- `ci.yml`: a lighter `build-windows` job that runs on every PR (build only, no
  publish) so packaging breakage is caught before tagging a release, plus the smoke
  test from (6) below.

### 5. Fix two POSIX-only assumptions blocking any native test run
These currently make it impossible to run the existing test fixtures on Windows at all,
independent of anything installer-related:
- `tests/conftest.py`'s `api` fixture (`conftest.py:420`) passes a pre-bound socket via
  `pass_fds=(api_sock.fileno(),)` and `uvicorn --fd ...` — `pass_fds` raises on Windows
  (`ValueError: pass_fds may not be used on Windows platforms`). Add a Windows branch
  that instead binds by passing `--host 127.0.0.1 --port <port>` directly to uvicorn.
- `ssh_agent` fixture (`conftest.py:350`) hardcodes `dir="/tmp"` for the agent socket
  path — switch to `tempfile.gettempdir()` (harmless no-op change on POSIX). On
  Windows this fixture should instead ensure the real OpenSSH Authentication Agent
  service is running (`Set-Service`/`Start-Service ssh-agent`) and use the well-known
  pipe, rather than trying to replicate the POSIX `-a <path>` pattern — that's what
  real Windows users will actually have, and it's what deliverable (1)'s transport
  needs to be tested against.

### 6. Native smoke test (`tests/test_windows_smoke.py`)
- Skipped unless `sys.platform == "win32"`.
- New `sshd_native` fixture: drives Windows' bundled `sshd.exe`/`ssh-keygen.exe` (from
  the `OpenSSH.Server` optional Windows capability) as a plain foreground subprocess
  bound to a free port — generating host keys up front, but **starting `sshd` only
  after the host certificate has been signed**. This sidesteps `tests/ssh.t`'s
  podman-specific `podman exec ... pkill -HUP sshd` reload step, which has no Windows
  equivalent and isn't needed if we just order things so no reload is required.
- The test itself is written as **plain Python/subprocess calls against the installed
  `pf.exe`/`pfa.exe`** (located via `shutil.which` after a silent install, not
  `uv run`), reproducing the same flow as `tests/ssh.t` (initialize → accept/login
  admin, host, and user identities → grant → sign host key → `pf ssh user@host
  whoami`) — not reusing cram. `tests/utils.py:run_cram` hardcodes
  `--shell /bin/bash`, which doesn't resolve on native Windows (GH's `windows-latest`
  ships Git Bash, but at `C:\Program Files\Git\bin\bash.exe`, not `/bin/bash`); a small
  dedicated Python test avoids depending on that being present and avoids fragile PATH
  translation between MSYS and native Windows paths.
- CI step sequence in the `build-windows` job: enable and start the OpenSSH
  Authentication Agent service (`Set-Service ssh-agent -StartupType Manual;
  Start-Service ssh-agent` — needs confirming this succeeds non-interactively on a
  `windows-latest` runner, which normally runs with admin rights), install the built
  `pf-setup.exe` silently (`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`), enable the
  OpenSSH Server Windows capability (`Add-WindowsCapability -Online -Name
  OpenSSH.Server~~~~0.0.1.0`), then `uv run pytest tests/test_windows_smoke.py`.

### 7. Docs
- Add a short "native Windows" install section to `docs/getting-started.md` (download
  and run `pf-setup.exe` from the GitHub Release), including the one-time
  `Set-Service`/`Start-Service ssh-agent` step if the agent isn't already enabled,
  alongside the existing pip/uv instructions.

## Local Windows test environment (native session, no WSL/CI round-trip needed)

This session now runs directly on the user's Windows 11 box (Bash tool = Git Bash,
PowerShell tool = native `powershell.exe`), both rooted at the real checkout
(`C:\Users\Mathieu\pf`) on native NTFS — no WSL interop, no UNC path, no
9p/wsl.localhost redirection layer to account for. That means most of this plan can
be built *and* tested locally, iteration-by-iteration, with CI reserved for
clean-machine confirmation rather than being the only place native Windows behavior
can be observed at all. Findings from a check of this machine:

- **`uv.exe` is installed** (`C:\Users\Mathieu\.local\bin\uv.exe`, on `PATH`) — drives
  `uv sync`/`uv run pytest`/PyInstaller directly via the PowerShell tool, no
  cross-VM invocation needed.
- **`ssh-agent` service is `Automatic`/`Running`** on this machine (not the
  disabled-by-default state a fresh install would have — likely enabled previously).
  That's exactly what deliverable (1), the named-pipe transport, needs to be tested
  against — it can be validated locally right now against the real
  `\\.\pipe\openssh-ssh-agent`, no setup required.
- OpenSSH **Client** is present (`ssh.exe`, `ssh-agent.exe`, `ssh-keygen.exe` under
  `C:\WINDOWS\System32\OpenSSH\`), but **`sshd.exe` is not** — the OpenSSH **Server**
  capability isn't installed. Needed only for deliverable (6), the native smoke test.
- `iscc.exe` (Inno Setup) is not installed. Needed only for deliverable (3).
- This session's shell runs **unelevated** (confirmed
  `IsInRole(Administrator)` is `False`) and can't self-elevate — installing the
  OpenSSH Server capability (`Add-WindowsCapability`) requires an elevated
  PowerShell, which only the user can open (UAC can't be driven non-interactively).
  Installing Inno Setup via `winget` may also prompt for elevation depending on the
  package's install scope.

Practical sequencing this enables: **deliverables (1), (2), and the Windows-only
fixture fixes in (5) can be implemented and tested end-to-end locally right now** —
everything they need (`uv.exe`, a running `ssh-agent` service, native `pytest`) is
already in place, run straight from this session via the PowerShell/Bash tools. No
CI push needed just to see whether `uv run pytest`, the named-pipe agent transport,
or the PyInstaller build work on Windows — that can be confirmed directly, in this
session, before ever opening a PR. Deliverables (3) and (6) still need one-time setup
the user has to run themselves in an elevated PowerShell, whenever we get to them:
```powershell
# For the Inno Setup step (3):
winget install --id JRSoftware.InnoSetup -e
# For the native smoke test (6):
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```
Once the user runs those, deliverables (3) and (6) become locally testable too, in
the same session, the same way. CI (`ci.yml`'s `build-windows` job) still matters as
the clean-machine gate — a fresh `windows-latest` runner has none of whatever this
dev box already had enabled/installed, so it catches setup this machine's
pre-existing state might mask — but it's no longer the *only* place native Windows
behavior can be exercised.

## Verification

1. **Local, fast iteration**: drive `uv.exe`/pytest/PyInstaller/`iscc.exe` directly
   against the checkout in this native Windows session — no push required, tightest
   feedback loop, available for deliverables (1), (2), and the (5) fixture fixes
   immediately, and for (3)/(6) once their one-time elevated setup is done.
2. Push to a branch and let the new `ci.yml` `build-windows` job run on a real
   `windows-latest` runner — confirms nothing was masked by this dev box's
   pre-existing state (permissions, path length, antivirus behavior, a clean machine
   without whatever's already installed/enabled here).
3. Inspect the uploaded installer artifact and the smoke test's pytest output/logs
   (reuse the existing per-test log capture pattern from `pf_log_directory`) before
   merging.
4. Tag a release and confirm `build-windows` in `release.yml` attaches `pf-setup.exe`
   to the GitHub Release correctly.

## Suggested PR breakdown
1. Windows named-pipe/AF_UNIX transport in `ssh/agent.py`, plus the actionable
   "agent service is disabled" error message, plus repurposing the existing spike on
   `ml/issue-51` to validate it against a real (enabled) Windows agent service.
2. PyInstaller spec + `windows-build` dependency group + `ci.yml` build-only job.
3. Inno Setup script + `release.yml` publish job.
4. `api`/`ssh_agent` fixture portability fixes + `sshd_native` fixture +
   `test_windows_smoke.py`, wired into the `ci.yml` job from (2).
5. Docs update.
