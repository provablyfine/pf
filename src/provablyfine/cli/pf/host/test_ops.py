from __future__ import annotations

import os
import pathlib
import stat
import sys

import provablyfine_client as pfc
import pytest

from . import ops


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes, owners, links or sh")


@posix_only
def test_system_ops_write_file_sets_mode_and_replaces_content(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "nested" / "file"
    system = ops.SystemOps()
    system.write_file(str(target), "one\n", 0o600)
    system.write_file(str(target), b"two\n", 0o640)
    assert target.read_bytes() == b"two\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


@posix_only
def test_system_ops_write_file_without_mode_keeps_the_existing_mode(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "file"
    target.write_text("old\n")
    target.chmod(0o600)
    ops.SystemOps().write_file(str(target), "new\n", None)
    assert target.read_text() == "new\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@posix_only
def test_system_ops_write_file_without_mode_uses_644_for_a_new_file(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "file"
    ops.SystemOps().write_file(str(target), "new\n", None)
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


@posix_only
def test_system_ops_make_dir_applies_the_mode_to_an_existing_directory(tmp_path: pathlib.Path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o755)
    ops.SystemOps().make_dir(str(directory), 0o700)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_system_ops_remove(tmp_path: pathlib.Path) -> None:
    file = tmp_path / "file"
    file.write_text("x")
    tree = tmp_path / "tree"
    (tree / "inner").mkdir(parents=True)
    (tree / "inner" / "leaf").write_text("x")
    system = ops.SystemOps()
    system.remove(str(file))
    system.remove(str(file))
    system.remove(str(tree), recursive=True)
    assert not file.exists()
    assert not tree.exists()


@posix_only
def test_system_ops_run_reports_failure_as_a_user_error() -> None:
    with pytest.raises(pfc.exceptions.UI, match="exit code 3"):
        ops.SystemOps().run(["sh", "-c", "exit 3"])


def test_system_ops_run_can_ignore_failure() -> None:
    ops.SystemOps().run(["sh", "-c", "exit 3"], check=False)
    ops.SystemOps().run(["/nonexistent/command"], check=False)


def test_system_ops_run_reports_a_missing_command() -> None:
    with pytest.raises(pfc.exceptions.UI, match="command not found"):
        ops.SystemOps().run(["/nonexistent/command"])


@posix_only
def test_system_ops_run_passes_stdin(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    ops.SystemOps().run(["sh", "-c", f"cat > {out}"], stdin=b"secret bytes")
    assert out.read_bytes() == b"secret bytes"


@posix_only
def test_query_reports_missing_commands_and_exit_codes() -> None:
    assert ops.run_query(["/nonexistent/command"]).returncode == 127
    result = ops.run_query(["sh", "-c", "echo hi; exit 2"])
    assert (result.returncode, result.stdout) == (2, "hi\n")


def test_dry_run_records_changes_and_does_not_apply_them(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "file"
    dry = ops.DryRunOps()
    dry.make_dir(str(tmp_path / "dir"), 0o700)
    dry.write_file(str(target), "content\n", 0o644)
    dry.remove(str(target), recursive=True)
    dry.run(["touch", str(target)], check=False, stdin=b"abc")
    assert dry.actions == [
        ops.MakeDir(str(tmp_path / "dir"), 0o700),
        ops.WriteFile(str(target), b"content\n", 0o644),
        ops.Remove(str(target), True),
        ops.Run(("touch", str(target)), False, b"abc"),
    ]
    assert not target.exists()
    assert not (tmp_path / "dir").exists()


@posix_only
def test_dry_run_reads_under_its_root(tmp_path: pathlib.Path) -> None:
    (tmp_path / "etc" / "ssh").mkdir(parents=True)
    (tmp_path / "etc" / "ssh" / "a.conf").write_text("A\n")
    (tmp_path / "etc" / "ssh" / "b.conf").write_text("B\n")
    tool = tmp_path / "usr" / "bin" / "tool"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    dry = ops.DryRunOps(root=tmp_path)
    assert dry.read_text("/etc/ssh/a.conf") == "A\n"
    assert dry.read_text("/etc/ssh/missing") is None
    assert dry.read_text("/etc/ssh") is None
    assert dry.list_dir("/etc/ssh") == ["/etc/ssh/a.conf", "/etc/ssh/b.conf"]
    assert dry.glob("/etc/ssh/*.conf") == ["/etc/ssh/a.conf", "/etc/ssh/b.conf"]
    assert dry.exists("/etc/ssh/a.conf")
    assert not dry.exists("/etc/ssh/nope")
    assert dry.is_executable("/usr/bin/tool")
    assert not dry.is_executable("/etc/ssh/a.conf")
    assert not dry.is_executable("/usr/bin/absent")


def test_dry_run_query_can_be_replaced() -> None:
    dry = ops.DryRunOps(query=lambda argv: ops.QueryResult(0, " ".join(argv)))
    assert dry.query(["a", "b"]) == ops.QueryResult(0, "a b")


def test_describe_shows_content_but_not_secrets() -> None:
    dry = ops.DryRunOps()
    dry.write_file("/etc/example", "line one\nline two\n", 0o644)
    dry.write_file("/var/lib/pf/key", "PRIVATE", 0o600, secret=True)
    dry.run(["tool", "--flag", "a b"], stdin=b"PRIVATE")
    dry.run(["maybe"], check=False)
    text = dry.describe()
    assert "  | line one\n  | line two\n" in text
    assert "PRIVATE" not in text
    quoted = '"a b"' if sys.platform == "win32" else "'a b'"
    assert f"run tool --flag {quoted}  (stdin: 7 bytes, not shown)" in text
    assert "run maybe  (failure ignored)" in text
    assert text.endswith("\n")


def test_make_dir_owner_is_recorded_and_described() -> None:
    dry = ops.DryRunOps()
    dry.make_dir("/var/db/pf/deadlines", 0o700, owner="nobody")
    assert dry.actions == [ops.MakeDir("/var/db/pf/deadlines", 0o700, "nobody")]
    assert dry.describe() == "mkdir -m 700 /var/db/pf/deadlines (owner nobody)\n"


def test_notes_are_recorded_and_described() -> None:
    dry = ops.DryRunOps()
    dry.note("check this")
    assert dry.actions == [ops.Note("check this")]
    assert dry.describe() == "note: check this\n"


def test_path_problem_accepts_a_system_binary() -> None:
    assert ops.SystemOps().path_problem("/bin/sh") is None


@posix_only
def test_path_problem_names_the_first_unsafe_component(tmp_path: pathlib.Path) -> None:
    tool = tmp_path / "opt" / "tool"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    tool.parent.chmod(0o775)
    problem = ops.SystemOps().path_problem(str(tool), trusted_uid=os.getuid())
    assert problem is not None
    assert str(tool.parent) in problem
    assert "written by its group or by others" in problem


@posix_only
def test_path_problem_refuses_a_file_that_others_can_write(tmp_path: pathlib.Path) -> None:
    tool = tmp_path / "tool"
    tool.write_text("x")
    tool.chmod(0o757)
    problem = ops.SystemOps().path_problem(str(tool), trusted_uid=os.getuid())
    assert problem is not None
    assert "757" in problem


@posix_only
def test_path_problem_refuses_a_path_owned_by_someone_else(tmp_path: pathlib.Path) -> None:
    tool = tmp_path / "tool"
    tool.write_text("x")
    tool.chmod(0o755)
    problem = ops.SystemOps().path_problem(str(tool), trusted_uid=os.getuid() + 1)
    assert problem is not None
    assert f"owned by uid {os.getuid()}" in problem


@posix_only
def test_path_problem_looks_through_symbolic_links(tmp_path: pathlib.Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    (unsafe / "tool").write_text("x")
    (unsafe / "tool").chmod(0o755)
    link = tmp_path / "link"
    link.symlink_to(unsafe / "tool")
    problem = ops.SystemOps().path_problem(str(link), trusted_uid=os.getuid())
    assert problem is not None
    assert "unsafe" in problem


@posix_only
def test_path_problem_reports_a_missing_path(tmp_path: pathlib.Path) -> None:
    problem = ops.SystemOps().path_problem(str(tmp_path / "missing"), trusted_uid=os.getuid())
    assert problem is not None
    assert "cannot inspect" in problem


@posix_only
def test_dry_run_path_problem_reads_under_its_root(tmp_path: pathlib.Path) -> None:
    tool = tmp_path / "opt" / "provablyfine" / "pf"
    tool.parent.mkdir(parents=True)
    tool.write_text("x")
    for path in (tool, tool.parent, tool.parent.parent):
        path.chmod(0o755)
    dry = ops.DryRunOps(root=tmp_path, trusted_uid=os.getuid())
    assert dry.path_problem("/opt/provablyfine/pf") is None
    tool.parent.chmod(0o775)
    problem = dry.path_problem("/opt/provablyfine/pf")
    assert problem is not None
    assert problem.startswith("/opt/provablyfine ")


def test_system_ops_run_hides_sudo_variables_from_children(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("KEEP_ME", "yes")
    out = tmp_path / "out"
    ops.SystemOps().run(["sh", "-c", f'echo "${{SUDO_USER-unset}} ${{SUDO_UID-unset}} $KEEP_ME" > {out}'])
    assert out.read_text() == "unset unset yes\n"


def test_describe_shows_utf16_content_as_text() -> None:
    dry = ops.DryRunOps()
    dry.write_file("C:\\task.xml", "<?xml version='1.0'?>\n<Task>caf\u00e9</Task>\n".encode("utf-16"), None)
    text = dry.describe()
    assert "  | <Task>caf\u00e9</Task>" in text
    assert "\x00" not in text
    assert "\ufffd" not in text
