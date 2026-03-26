import os
import subprocess
import tempfile

import pytest
import textual.widgets

import pf.client
import pf.tui.app
import pf.tui.async_client
import pf.tui.grant_edit


def _run(args, env, **kwargs):
    return subprocess.run(args, env=env, check=True, capture_output=True, **kwargs)


def _setup(api, tmpdir):
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}"}
    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    config_file = os.path.join(tmpdir, "config.json")

    _run(["pf", "-c", config_file, "config", "--directory", directory_url], env)
    result = _run(["pfa", "-c", config_file, "initialize"], env, text=True)
    invitation = result.stdout.strip()

    account_key = os.path.join(tmpdir, "account")
    _run(["ssh-keygen", "-t", "ed25519", "-f", account_key, "-N", ""], env)
    _run(["pf", "-c", config_file, "accept", f"--invitation={invitation}", f"--key={account_key}"], env)

    session_key = os.path.join(tmpdir, "session")
    _run(["ssh-keygen", "-t", "ed25519", "-f", session_key, "-N", ""], env)
    _run(["pf", "-c", config_file, "login", f"--session-key={session_key}"], env)

    cfg = pf.client.Config.load(config_file)
    http_client = pf.client.Client(cfg).session_auth(cfg.session_key)
    return pf.tui.async_client.AsyncClient(http_client)


@pytest.mark.anyio
async def test_tui_grant_edit_identity_fails(api):
    """Editing an identity grant on the root role must fail with an error notification.

    The default user is a member of the root role (the very role being edited),
    so the API rejects the PATCH and the TUI shows an error notification.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            # Wait for the role list to load
            await pilot.pause(1.0)

            # Root role is the only role; press enter to open the role view
            await pilot.press("enter")
            await pilot.pause(0.5)

            # Tab to the grants DataTable; the identity grant is row 0
            await pilot.press("tab")
            await pilot.press("enter")

            # Wait for the GrantEditScreen and IdentityGrantEditWidget.on_mount
            # (three API calls: identities, tags, boundaries)
            await pilot.pause(3.0)

            # Enable filter.name to make the grant differ from its saved state
            await pilot.click("#filter-name Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"root")
            await pilot.pause(0.1)

            # Confirm grant edits (returns to RoleViewScreen, no DB write yet)
            await pilot.press("ctrl+s")

            # Save the role (triggers PATCH for changed grant_list, which should fail)
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")

            # Wait for the PATCH response and notification
            await pilot.pause(2.0)

        error_notifications = [n for n in app._notifications if n.severity == "error"]
        assert error_notifications, "Expected an error notification after saving identity grant"


async def _setup_role_with_grant(auth: pf.tui.async_client.AsyncClient, grant_dict: dict) -> int:
    response = await auth.post(auth.directory.role, json={"name": "test-role"})
    role_id = response.json()["id"]
    await auth.patch(f"{auth.directory.role}/{role_id}", json={"grant_list": [grant_dict]})
    return role_id


async def _get_grant(auth: pf.tui.async_client.AsyncClient, role_id: int) -> dict:
    response = await auth.get(auth.directory.role, params={"id": role_id})
    return response.json()["roles"][0]["grant_list"][0]


@pytest.mark.anyio
async def test_tui_role_grant_edit(api):
    """Edit a role grant: set filter.name and enable all 7 permissions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        # Pre-create role "aaa" to use as filter.name target.
        # It sorts before "root" alphabetically, so it will be the first option
        # after the blank entry in the Select dropdown.
        await auth.post(auth.directory.role, json={"name": "aaa"})

        # Create test role with a role grant.
        # Role list order: root=row0, aaa=row1, test-role=row2.
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("role"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down", "down")  # navigate to test-role (row 2)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(1.0)  # RoleGrantEditWidget.on_mount: 1 API call

            await pilot.click("#filter-name Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"aaa")
            await pilot.pause(0.1)

            # Enable all 7 permissions in the SelectionList.
            # Options (compose order): create=0, read=1, update.name=2,
            # update.description=3, update.member_list=4, update.grant_list=5, delete=6.
            # Focus without clicking to avoid an accidental item toggle.
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause(0.1)
            for _ in range(7):
                await pilot.press("space")  # toggle current item
                await pilot.press("down")  # advance cursor (no-op on last item)

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name"] == "aaa"
    assert grant["permission"]["create"] is True
    assert grant["permission"]["read"] is True
    assert grant["permission"]["update"]["name"] is True
    assert grant["permission"]["update"]["description"] is True
    assert grant["permission"]["update"]["member_list"] is True
    assert grant["permission"]["update"]["grant_list"] is True
    assert grant["permission"]["delete"] is True


@pytest.mark.anyio
async def test_tui_identity_grant_edit_filters(api):
    """Edit an identity grant: set filter.name, filter.tag_list, filter.boundary_list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        # Pre-create the tag and boundary used in filter values.
        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        await auth.post(auth.directory.boundary, json={"name": "zone1"})

        # Create test role with an identity grant.
        # Role list order: root=row0, test-role=row1.
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("identity"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(3.0)  # IdentityGrantEditWidget.on_mount: 3 API calls

            await pilot.click("#filter-name Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"root")
            await pilot.pause(0.1)

            # filter.tag_list: enable CheckboxInput and type "env=prod".
            await pilot.click("#filter-tagged-by Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"env=prod")
            await pilot.pause(0.1)

            # filter.boundary_list: enable CheckboxInput and type "zone1".
            await pilot.click("#filter-bounded-by Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"zone1")
            await pilot.pause(0.1)

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name"] == "root"
    assert grant["filter"]["tag_list"] == [{"name": "env", "value": "prod"}]
    assert grant["filter"]["boundary_list"] == ["zone1"]


@pytest.mark.anyio
async def test_tui_identity_grant_edit_permissions(api):
    """Edit an identity grant: enable all permission fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        # Pre-create tag and boundary required by permission fields.
        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        await auth.post(auth.directory.boundary, json={"name": "zone1"})

        # Create test role with an identity grant.
        # Role list order: root=row0, test-role=row1.
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("identity"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(3.0)  # IdentityGrantEditWidget.on_mount: 3 API calls

            # permission.create: enable (also enables the sub-fields container).
            await pilot.click("#permission-create")
            await pilot.pause(0.1)

            # permission.create.allowed_tag_list: enable and type "env=prod".
            await pilot.click("#permission-create-allowed-tags Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"env=prod")
            await pilot.pause(0.1)

            # permission.create.required_boundary_list: enable and type "zone1".
            await pilot.click("#permission-create-req-boundaries Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"zone1")
            await pilot.pause(0.1)

            # Simple permission checkboxes.
            await pilot.click("#permission-read")
            await pilot.pause(0.1)
            await pilot.click("#permission-update-name")
            await pilot.pause(0.1)
            await pilot.click("#permission-delete")
            await pilot.pause(0.1)

            # permission.add_tag_list: enable and type "env=prod".
            await pilot.click("#permission-add-tag Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"env=prod")
            await pilot.pause(0.1)

            # permission.del_tag_list: enable and type "env=prod".
            await pilot.click("#permission-del-tag Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"env=prod")
            await pilot.pause(0.1)

            # permission.invite_list: enable and type "email".
            await pilot.click("#permission-invite Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"email")
            await pilot.pause(0.1)

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    perm = grant["permission"]
    assert perm["create"]["allowed"] is True
    assert perm["create"]["allowed_tag_list"] == [{"name": "env", "value": "prod"}]
    assert perm["create"]["required_boundary_list"] == ["zone1"]
    assert perm["read"] is True
    assert perm["update"]["name"] is True
    assert perm["delete"] is True
    assert perm["add_tag_list"] == [{"name": "env", "value": "prod"}]
    assert perm["del_tag_list"] == [{"name": "env", "value": "prod"}]
    assert perm["invite_list"] == ["email"]


@pytest.mark.anyio
async def test_tui_tag_grant_edit(api):
    """Edit a tag grant: set filter.name_value and enable create + read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("tag"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(1.0)  # TagGrantEditWidget.on_mount: 1 API call

            await pilot.click("#filter-name-value Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"env=prod")
            await pilot.pause(0.1)

            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause(0.1)
            await pilot.press("space")  # create=0
            await pilot.press("down")
            await pilot.press("space")  # read=1

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name_value"] == {"name": "env", "value": "prod"}
    assert grant["permission"]["create"] is True
    assert grant["permission"]["read"] is True
    assert grant["permission"]["delete"] is False


@pytest.mark.anyio
async def test_tui_boundary_grant_edit(api):
    """Edit a boundary grant: set filter.name and enable create + read + update.name."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        await auth.post(auth.directory.boundary, json={"name": "zone1"})
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("boundary"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(1.0)  # BoundaryGrantEditWidget.on_mount: 1 API call

            await pilot.click("#filter-name Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"zone1")
            await pilot.pause(0.1)

            # SelectionList: create=0, read=1, update.name=2, ...
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause(0.1)
            await pilot.press("space")  # create=0
            await pilot.press("down")
            await pilot.press("space")  # read=1
            await pilot.press("down")
            await pilot.press("space")  # update.name=2

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name"] == "zone1"
    assert grant["permission"]["create"] is True
    assert grant["permission"]["read"] is True
    assert grant["permission"]["update"]["name"] is True
    assert grant["permission"]["update"]["description"] is False


@pytest.mark.anyio
async def test_tui_tenant_grant_edit(api):
    """Edit a tenant grant: leave filter.id as wildcard and enable read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("tenant"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(1.0)  # TenantGrantEditWidget.on_mount: 1 API call

            # SelectionList: create=0, read=1, ...
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause(0.1)
            await pilot.press("down")  # move to read=1
            await pilot.press("space")  # toggle read

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["id"] is None
    assert grant["permission"]["read"] is True
    assert grant["permission"]["create"] is False


@pytest.mark.anyio
async def test_tui_ssh_grant_edit(api):
    """Edit an SSH grant: set filter.name, restrict username_list, enable permit_pty."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        await auth.post(auth.directory.boundary, json={"name": "zone1"})
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("ssh"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause(1.0)
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause(0.5)
            await pilot.press("tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause(3.0)  # SshGrantEditWidget.on_mount: 3 API calls

            await pilot.click("#filter-name Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"root")
            await pilot.pause(0.1)

            # username_list: enable checkbox and type "alice"
            await pilot.click("#perm-username-list Checkbox")
            await pilot.pause(0.1)
            await pilot.press(*"alice")
            await pilot.pause(0.1)

            await pilot.click("#perm-permit-pty")

            await pilot.press("ctrl+s")  # confirm grant edits
            await pilot.pause(0.5)
            await pilot.press("ctrl+s")  # save role
            await pilot.pause(2.0)

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name"] == "root"
    assert grant["permission"]["username_list"] == ["alice"]
    assert grant["permission"]["force_command_list"] is None
    assert grant["permission"]["permit_pty"] is True
    assert grant["permission"]["permit_user_rc"] is False
