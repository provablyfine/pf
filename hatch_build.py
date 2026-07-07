from __future__ import annotations

import hashlib
import os
import pathlib
import platform
import stat
import tarfile
import typing
import urllib.request

import hatchling.builders.hooks.plugin.interface

FRPC_VERSION = "0.69.1"

FRPC_SHA256: dict[str, str] = {
    "linux-amd64": "7be257b72dbbc60bcb3e0e25a5afd1dfac7b63f897084864d3c956dd3d5674e1",
    "linux-arm64": "bbc0c75e896af3f292fb46ba09c844a04fa9b5ea3530c039c7af20637f836355",
    "darwin-amd64": "2bc26d02100ef333f2712149ea5997dc530dc0eefac64f4be41cb0f49d032f40",
    "darwin-arm64": "310012e2f1dcf3cdde2605d29b95340b686c94d1680a23711d58efeffc02f64e",
}

WHEEL_TAGS: dict[str, str] = {
    "linux-amd64": "linux_x86_64",
    "linux-arm64": "linux_aarch64",
    "darwin-amd64": "macosx_10_15_x86_64",
    "darwin-arm64": "macosx_11_0_arm64",
}


class CustomBuildHook(hatchling.builders.hooks.plugin.interface.BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, typing.Any]) -> None:
        system = platform.system().lower()
        # Allow cross-building via env var (e.g. CI building aarch64 wheel on x86_64)
        machine = os.environ.get("HATCH_TARGET_ARCH", platform.machine()).lower()
        os_name = {"linux": "linux", "darwin": "darwin"}.get(system, system)
        arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
        target = f"{os_name}-{arch}"

        dest = pathlib.Path(self.root) / "src" / "provablyfine" / "bin" / "frpc"
        dest.parent.mkdir(parents=True, exist_ok=True)

        if target not in FRPC_SHA256:
            self.app.display_warning(
                f"No frpc SHA256 for platform {target!r}; skipping bundled frpc (PATH fallback will be used)."
            )
            return

        tarball_name = f"frp_{FRPC_VERSION}_{os_name}_{arch}.tar.gz"
        url = f"https://github.com/fatedier/frp/releases/download/v{FRPC_VERSION}/{tarball_name}"
        cache_dir = pathlib.Path(self.root) / ".cache"
        cache_dir.mkdir(exist_ok=True)
        tarball_path = cache_dir / tarball_name

        if not tarball_path.exists():
            self.app.display_info(f"Downloading {tarball_name} ...")
            urllib.request.urlretrieve(url, tarball_path)

        digest = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
        if digest != FRPC_SHA256[target]:
            tarball_path.unlink()
            raise RuntimeError(f"SHA256 mismatch for {tarball_name}: expected {FRPC_SHA256[target]}, got {digest}")

        with tarfile.open(tarball_path) as tf:
            member_name = f"frp_{FRPC_VERSION}_{os_name}_{arch}/frpc"
            member = tf.getmember(member_name)
            member.name = "frpc"
            tf.extract(member, path=dest.parent, filter="data")

            licenses_dir = pathlib.Path(self.root) / "src" / "provablyfine" / "licenses"
            licenses_dir.mkdir(parents=True, exist_ok=True)
            for name in ("LICENSE", "NOTICE"):
                try:
                    lic = tf.getmember(f"frp_{FRPC_VERSION}_{os_name}_{arch}/{name}")
                    lic.name = f"frpc-{name}"
                    tf.extract(lic, path=licenses_dir, filter="data")
                except KeyError:
                    pass

        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.app.display_info(f"Bundled frpc {FRPC_VERSION} for {target}")

        if target in WHEEL_TAGS:
            build_data["tag"] = f"py3-none-{WHEEL_TAGS[target]}"
