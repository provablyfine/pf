# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the macOS client package. Produces a single onedir
# payload containing the pf, pfa, and pfat executables. Built natively on
# the target architecture: PyInstaller output is not cross-architecture.

import os

ENTRIES = [
    ("pf", os.path.join(SPECPATH, "..", "linux", "pf_entry.py")),
    ("pfa", os.path.join(SPECPATH, "..", "linux", "pfa_entry.py")),
    ("pfat", os.path.join(SPECPATH, "..", "linux", "pfat_entry.py")),
]

analyses = []
for name, script in ENTRIES:
    a = Analysis(
        [script],
        pathex=[],
        binaries=[],
        datas=[],
        hiddenimports=[],
        hookspath=[],
        hooksconfig={},
        runtime_hooks=[],
        excludes=[],
        noarchive=False,
        optimize=0,
    )
    pyz = PYZ(a.pure)

    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    analyses.append((a, exe))

# COLLECT dedupes identical files; the pf/pfa/pfat analyses share the same
# venv, so overlapping dependencies collapse into one copy on disk.
coll = COLLECT(
    *[exe for _, exe in analyses],
    *[item for a, _ in analyses for item in (a.binaries, a.datas)],
    strip=False,
    upx=False,
    name="provablyfine",
)
