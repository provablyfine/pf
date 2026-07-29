import os
import pathlib
import platform
import subprocess
import sys

import hatchling.builders.hooks.plugin.interface

_RUST_TARGET_TRIPLES: dict[str, str] = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
}


class CustomBuildHook(hatchling.builders.hooks.plugin.interface.BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:  # type: ignore[override]
        target_arch = os.environ.get("HATCH_TARGET_ARCH")

        if target_arch == "unsupported":
            return

        if sys.platform != "linux":
            return

        arch = target_arch or platform.machine()
        ver = f"{sys.version_info.major}{sys.version_info.minor}"
        build_data["tag"] = f"cp{ver}-cp{ver}-linux_{arch}"

        nss_src = pathlib.Path(self.root) / "src" / "nss" / "libnss_provablyfine"
        env = os.environ.copy()
        aleash_ca = pathlib.Path("/tmp/aleash-ca.pem")
        if aleash_ca.exists() and "CARGO_HTTP_CAINFO" not in env:
            env["CARGO_HTTP_CAINFO"] = str(aleash_ca)

        host_machine = platform.machine()
        if target_arch and target_arch != host_machine:
            rust_triple = _RUST_TARGET_TRIPLES.get(target_arch)
            if rust_triple is None:
                raise RuntimeError(f"No known Rust triple for HATCH_TARGET_ARCH={target_arch!r}")
            subprocess.run(
                ["cargo", "build", "--release", "--target", rust_triple],
                cwd=str(nss_src),
                check=True,
                env=env,
            )
            so_src = nss_src / "target" / rust_triple / "release" / "libnss_provablyfine.so"
        else:
            subprocess.run(
                ["cargo", "build", "--release"],
                cwd=str(nss_src),
                check=True,
                env=env,
            )
            so_src = nss_src / "target" / "release" / "libnss_provablyfine.so"

        build_data["force_include"][str(so_src)] = "provablyfine/_nss/libnss_provablyfine.so"
