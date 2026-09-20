# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the Linux client packages. Produces a single onedir
# payload containing the pf, pfa, and pfat executables. The payload is
# platform-neutral within a glibc floor: it must be built in the oldest
# supported environment (rockylinux:9, glibc 2.34) so the resulting binaries
# run on Ubuntu 22.04+, Debian 12+, RHEL 9+, and current Fedora.

ENTRIES = [
    ("pf", "pf_entry.py"),
    ("pfa", "pfa_entry.py"),
    ("pfat", "pfat_entry.py"),
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
