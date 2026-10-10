from __future__ import annotations

import os
import pathlib
import sys

import pytest

from . import common_steps, ops

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes, owners and links")

PREFIXES = ("/usr/bin",)


def _install(tmp_path: pathlib.Path) -> ops.DryRunOps:
    tool = tmp_path / "usr" / "bin" / "pf"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\n")
    for path in (tool, tool.parent, tool.parent.parent):
        path.chmod(0o755)
    return ops.DryRunOps(root=tmp_path)


@posix_only
def test_a_correct_install_has_no_problem(tmp_path: pathlib.Path) -> None:
    assert common_steps.pf_install_problem(_install(tmp_path), "/usr/bin/pf", PREFIXES) is None


@posix_only
def test_a_pf_outside_the_system_directories_is_refused(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    (tmp_path / "opt").mkdir()
    (tmp_path / "opt" / "pf").write_text("x")
    (tmp_path / "opt" / "pf").chmod(0o755)
    (tmp_path / "opt").chmod(0o755)
    assert common_steps.pf_install_problem(dry, "/opt/pf", PREFIXES) == "/opt/pf is not in /usr/bin"


@posix_only
def test_the_first_directory_that_others_can_write_is_named(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    (tmp_path / "usr" / "bin").chmod(0o775)
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES)
    assert problem == "/usr/bin can be written by its group or by others (mode 775)"


@posix_only
def test_a_file_that_others_can_write_is_refused(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    (tmp_path / "usr" / "bin" / "pf").chmod(0o757)
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES)
    assert problem == "/usr/bin/pf can be written by its group or by others (mode 757)"


@posix_only
def test_a_path_owned_by_someone_else_is_refused(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES, trusted_uid=os.getuid() + 1)
    assert problem == f"/usr/bin/pf is owned by uid {os.getuid()}, not {os.getuid() + 1}"


@posix_only
@pytest.mark.parametrize("mode", [0o750, 0o754, 0o751])
def test_a_file_that_others_cannot_read_and_run_is_refused(tmp_path: pathlib.Path, mode: int) -> None:
    dry = _install(tmp_path)
    (tmp_path / "usr" / "bin" / "pf").chmod(mode)
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES)
    assert problem == f"/usr/bin/pf is closed to other users (mode {mode:o})"


@posix_only
def test_a_directory_that_others_cannot_search_is_refused(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    (tmp_path / "usr").chmod(0o750)
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES)
    assert problem == "/usr is closed to other users (mode 750)"


@posix_only
def test_a_missing_file_is_reported(tmp_path: pathlib.Path) -> None:
    dry = _install(tmp_path)
    (tmp_path / "usr" / "bin" / "pf").unlink()
    problem = common_steps.pf_install_problem(dry, "/usr/bin/pf", PREFIXES)
    assert problem is not None
    assert problem.startswith("cannot inspect /usr/bin/pf")


@posix_only
def test_a_symbolic_link_is_judged_by_its_target(tmp_path: pathlib.Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    (unsafe / "pf").write_text("x")
    (unsafe / "pf").chmod(0o755)
    link = tmp_path / "pf"
    link.symlink_to(unsafe / "pf")
    problem = common_steps.pf_install_problem(ops.SystemOps(), str(link), (str(unsafe),), trusted_uid=os.getuid())
    assert problem == f"{unsafe} can be written by its group or by others (mode 777)"
