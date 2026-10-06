from __future__ import annotations

import os
import pathlib
import stat

import provablyfine_client as pfc
import pytest

from . import ops


def test_system_ops_write_file_sets_mode_and_replaces_content(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "nested" / "file"
    system = ops.SystemOps()
    system.write_file(str(target), "one\n", 0o600)
    system.write_file(str(target), b"two\n", 0o640)
    assert target.read_bytes() == b"two\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_system_ops_write_file_without_mode_keeps_the_existing_mode(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "file"
    target.write_text("old\n")
    target.chmod(0o600)
    ops.SystemOps().write_file(str(target), "new\n", None)
    assert target.read_text() == "new\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_system_ops_write_file_without_mode_uses_644_for_a_new_file(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "file"
    ops.SystemOps().write_file(str(target), "new\n", None)
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


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


def test_system_ops_run_reports_failure_as_a_user_error() -> None:
    with pytest.raises(pfc.exceptions.UI, match="exit code 3"):
        ops.SystemOps().run(["sh", "-c", "exit 3"])


def test_system_ops_run_can_ignore_failure() -> None:
    ops.SystemOps().run(["sh", "-c", "exit 3"], check=False)
    ops.SystemOps().run(["/nonexistent/command"], check=False)


def test_system_ops_run_reports_a_missing_command() -> None:
    with pytest.raises(pfc.exceptions.UI, match="command not found"):
        ops.SystemOps().run(["/nonexistent/command"])


def test_system_ops_run_passes_stdin(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    ops.SystemOps().run(["sh", "-c", f"cat > {out}"], stdin=b"secret bytes")
    assert out.read_bytes() == b"secret bytes"


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
    assert "run tool --flag 'a b'  (stdin: 7 bytes, not shown)" in text
    assert "run maybe  (failure ignored)" in text
    assert os.linesep in text
