import json
import os
import pathlib
import sys

import provablyfine_client as pfc
import pytest

from . import configuration


def test_config_save_then_load_round_trips_as_current_context(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme")
    cfg.save(path)

    loaded = configuration.Config.load(path)
    assert loaded.directory_url == cfg.directory_url
    assert loaded.context_name == "acme"

    registry = configuration.Registry.load(path)
    assert registry.current == "acme"
    assert registry.previous is None
    assert set(registry.contexts) == {"acme"}


def test_config_save_updates_in_place_when_context_name_is_set(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme")
    cfg.save(path)

    cfg.auth_name = "sso"
    cfg.save(path)

    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"acme"}
    assert registry.contexts["acme"].auth_name == "sso"


def test_config_save_auto_names_collide_with_numeric_suffix(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    first = configuration.Config(directory_url="https://a.example.com/pf/t/acme/directory", tenant_name="acme")
    first.save(path)
    second = configuration.Config(directory_url="https://b.example.com/pf/t/acme/directory", tenant_name="acme")
    second.save(path)

    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"acme", "acme-2"}
    assert registry.current == "acme-2"
    assert registry.previous == "acme"


def test_config_save_refuses_when_ephemeral(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    other = configuration.Config(directory_url="https://example.com/pf/t/root/directory", tenant_name="root")
    other.save(path)

    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme")
    cfg.ephemeral = True
    with pytest.raises(RuntimeError):
        cfg.save(path)

    # An ephemeral config refusing to save must not touch the registry at all,
    # even though other (non-ephemeral) contexts already live on disk.
    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"root"}


def test_config_load_raises_ui_when_registry_is_empty(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    with pytest.raises(pfc.exceptions.UI):
        configuration.Config.load(path)


def test_registry_load_migrates_legacy_flat_config(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    legacy = {
        "directory_url": "https://example.com/pf/t/acme/directory",
        "tenant_name": "acme",
        "account_key_fingerprint": "SHA256:abc",
        "auth_name": "default",
    }
    with open(path, "w") as f:
        json.dump(legacy, f)

    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"acme"}
    assert registry.current == "acme"
    assert registry.contexts["acme"].account_key_fingerprint == "SHA256:abc"

    # Migration writes the new shape back to disk, silently and once.
    with open(path) as f:
        on_disk = json.load(f)
    assert "contexts" in on_disk
    assert on_disk["current"] == "acme"


def test_registry_load_missing_file_returns_empty_registry(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "does-not-exist.json")
    registry = configuration.Registry.load(path)
    assert registry.contexts == {}
    assert registry.current is None


def test_set_session_fingerprint_only_touches_session_fields(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    cfg = configuration.Config(
        directory_url="https://example.com/pf/t/acme/directory",
        auth_name="corp",
        role_id=7,
        session_key_file="/old/key",
    )
    cfg.save(path)

    configuration.Registry.set_session_fingerprint(path, "https://example.com/pf/t/acme/directory", "SHA256:abc")

    saved = configuration.Config.load(path)
    assert saved.session_key_fingerprint == "SHA256:abc"
    assert saved.session_key_file is None
    assert saved.auth_name == "corp"
    assert saved.role_id == 7


def test_set_session_fingerprint_follows_a_rename(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    url = "https://example.com/pf/t/acme/directory"
    configuration.Config(directory_url=url, tenant_name="acme").save(path)
    with configuration.Registry.transaction(path) as registry:
        registry.rename("acme", "work")

    configuration.Registry.set_session_fingerprint(path, url, "SHA256:abc")

    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"work"}
    assert registry.contexts["work"].session_key_fingerprint == "SHA256:abc"


def test_config_save_after_a_rename_elsewhere_updates_the_renamed_context(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme")
    cfg.save(path)
    with configuration.Registry.transaction(path) as registry:
        registry.rename("acme", "work")

    cfg.auth_name = "sso"
    cfg.save(path)

    registry = configuration.Registry.load(path)
    assert set(registry.contexts) == {"work"}
    assert registry.contexts["work"].auth_name == "sso"
    assert cfg.context_name == "work"


def test_config_save_refuses_a_second_context_for_the_same_directory_url(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    url = "https://example.com/pf/t/acme/directory"
    configuration.Config(directory_url=url, tenant_name="acme").save(path)

    with pytest.raises(pfc.exceptions.UI, match="acme"):
        configuration.Config(directory_url=url, tenant_name="acme").save(path)
    with pytest.raises(pfc.exceptions.UI, match="acme"):
        configuration.Registry.ensure_url_available(path, url)

    assert set(configuration.Registry.load(path).contexts) == {"acme"}
    configuration.Registry.ensure_url_available(path, "https://example.com/pf/t/other/directory")


def test_transaction_writes_nothing_when_the_body_raises(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme").save(path)

    with pytest.raises(pfc.exceptions.UI):
        with configuration.Registry.transaction(path) as registry:
            registry.rename("acme", "work")
            registry.delete("acme")  # "acme" no longer exists

    assert set(configuration.Registry.load(path).contexts) == {"acme"}


def test_registry_delete_refuses_the_current_context() -> None:
    registry = configuration.Registry(
        contexts={
            "a": configuration.Config(directory_url="https://example.com/pf/t/a/directory", tenant_name="a"),
            "b": configuration.Config(directory_url="https://example.com/pf/t/b/directory", tenant_name="b"),
        },
        current="a",
        previous="b",
    )
    with pytest.raises(pfc.exceptions.UI):
        registry.delete("a")
    registry.delete("b")
    assert registry.previous is None


def test_leftover_lock_file_does_not_block_writers(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "config.json")
    # What a crashed writer used to leave behind.
    pathlib.Path(path + ".lock").write_text("")

    configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme").save(path)

    assert set(configuration.Registry.load(path).contexts) == {"acme"}


def test_writer_times_out_naming_the_lock_file_while_another_holds_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = str(tmp_path / "config.json")
    monkeypatch.setattr(configuration, "_LOCK_TIMEOUT_SECONDS", 0.2)

    with configuration.Registry.transaction(path):
        with pytest.raises(pfc.exceptions.UI, match=r"config\.json\.lock"):
            configuration.Registry.set_session_fingerprint(path, "https://example.com/pf/t/acme/directory", None)

    # Released again once the holder is done.
    configuration.Registry.set_session_fingerprint(path, "https://example.com/pf/t/acme/directory", None)


def test_readers_do_not_take_the_lock(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = str(tmp_path / "config.json")
    configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme").save(path)
    monkeypatch.setattr(configuration, "_LOCK_TIMEOUT_SECONDS", 0.2)

    with configuration.Registry.transaction(path):
        assert configuration.Config.load(path).context_name == "acme"


@pytest.mark.skipif(
    sys.platform == "win32", reason="directory permissions do not make a directory read-only on Windows"
)
@pytest.mark.skipif(sys.platform != "win32" and os.geteuid() == 0, reason="root ignores directory permissions")
def test_reading_needs_no_write_access_to_the_config_directory(tmp_path: pathlib.Path) -> None:
    config_dir = tmp_path / "ro"
    config_dir.mkdir()
    path = str(config_dir / "config.json")
    configuration.Config(directory_url="https://example.com/pf/t/acme/directory", tenant_name="acme").save(path)
    legacy_path = str(config_dir / "legacy.json")
    with open(legacy_path, "w") as f:
        json.dump({"directory_url": "https://example.com/pf/t/old/directory", "tenant_name": "old"}, f)
    config_dir.chmod(0o500)
    try:
        assert configuration.Config.load(path).context_name == "acme"
        assert set(configuration.Registry.load(legacy_path).contexts) == {"old"}
        assert not os.path.exists(path + ".lock.new")

        with pytest.raises(pfc.exceptions.UI, match="Unable to write"):
            configuration.Config.load(path).save(path)
    finally:
        config_dir.chmod(0o700)
