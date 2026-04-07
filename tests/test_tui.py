import os
import subprocess
import tempfile

import pytest
import textual.widgets
from textual.worker import WorkerCancelled, WorkerFailed

import pf.client
import pf.tui.app
import pf.tui.async_client
import pf.tui.grant_edit


async def _wait(pilot, app=None):
    """Wait for pending events then all workers to complete.

    Structure:
    1. pilot.pause() — drain event loop, let message handlers run
    2. wait_for_complete() — wait for @work-decorated methods (save/add/delete)
    3. pilot.pause() — let UI re-render after worker result (notifications, updates)
    """
    await pilot.pause()  # let pending events dispatch and workers start
    target = app if app is not None else pilot.app
    try:
        await target.workers.wait_for_complete()  # wait for save/add/delete
    except (WorkerFailed, WorkerCancelled):
        pass  # errors already handled by app._handle_exception → notify()
    await pilot.pause()  # let UI re-render (notifications, table updates)


def _run(args, env, **kwargs):
    return subprocess.run(args, env=env, check=True, capture_output=True, **kwargs)


def _setup(api, tmpdir):
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}"}
    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    config_file = os.path.join(tmpdir, "config.json")

    account_key = os.path.join(tmpdir, "account")
    _run(["ssh-keygen", "-t", "ed25519", "-f", account_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "initialize", directory_url, f"--key={account_key}"], env)

    session_key = os.path.join(tmpdir, "session")
    _run(["ssh-keygen", "-t", "ed25519", "-f", session_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "login", f"--session-key={session_key}"], env)

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
            await pilot.pause()  # app startup (no HTTP)
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount calls list_roles()

            # Root role is the only role; press enter to open the role view
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount (no API)

            # Tab to the grants DataTable; the identity grant is row 0
            await pilot.press("tab", "tab", "tab")
            await pilot.press("enter")

            # Wait for the GrantEditScreen and IdentityGrantEditWidget.on_mount
            # (three API calls: identities, tags, boundaries)
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityGrantEditWidget.on_mount + 3 APIs

            # Enable filter.name to make the grant differ from its saved state
            await pilot.click("#filter-name Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"root")
            await pilot.pause()  # UI event settle

            # Confirm grant edits (returns to RoleViewScreen, no DB write yet)
            await pilot.press("ctrl+s")

            # Save the role (triggers PATCH for changed grant_list, which should fail)
            await _wait(pilot, app)  # action_edit_grant worker completes
            await pilot.press("ctrl+s")

            # Wait for the PATCH response and notification
            await _wait(pilot, app)  # action_save worker + error notification

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount calls list_roles()
            await pilot.press("down", "down")  # navigate to test-role (row 2)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount (no API)
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleGrantEditWidget.on_mount calls list_roles()

            await pilot.click("#filter-name Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"aaa")
            await pilot.pause()  # UI event settle

            # Enable all 7 permissions in the SelectionList.
            # Options (compose order): create=0, read=1, update.name=2,
            # update.description=3, update.member_list=4, update.grant_list=5, delete=6.
            # Focus without clicking to avoid an accidental item toggle.
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause()  # UI event settle
            for _ in range(7):
                await pilot.press("space")  # toggle current item
                await pilot.press("down")  # advance cursor (no-op on last item)

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker completes
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker + success notification

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityGrantEditWidget.on_mount (3 APIs: identities, tags, boundaries)

            await pilot.click("#filter-name Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"root")
            await pilot.pause()  # UI event settle

            # filter.tag_list: enable CheckboxInput and type "env=prod".
            await pilot.click("#filter-tagged-by Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"env=prod")
            await pilot.pause()  # UI event settle

            # filter.boundary_list: enable CheckboxInput and type "zone1".
            await pilot.click("#filter-bounded-by Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"zone1")
            await pilot.pause()  # UI event settle

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker completes
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityGrantEditWidget.on_mount (3 APIs)

            # permission.create: enable (also enables the sub-fields container).
            await pilot.click("#permission-create")
            await pilot.pause()  # UI event settle

            # permission.create.allowed_tag_list: enable and type "env=prod".
            await pilot.click("#permission-create-allowed-tags Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"env=prod")
            await pilot.pause()  # UI event settle

            # permission.create.required_boundary_list: enable and type "zone1".
            await pilot.click("#permission-create-req-boundaries Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"zone1")
            await pilot.pause()  # UI event settle

            # Simple permission checkboxes.
            await pilot.click("#permission-read")
            await pilot.pause()  # UI event settle
            await pilot.click("#permission-update-name")
            await pilot.pause()  # UI event settle
            await pilot.click("#permission-delete")
            await pilot.pause()  # UI event settle

            # permission.add_tag_list: enable and type "env=prod".
            await pilot.click("#permission-add-tag Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"env=prod")
            await pilot.pause()  # UI event settle

            # permission.del_tag_list: enable and type "env=prod".
            await pilot.click("#permission-del-tag Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"env=prod")
            await pilot.pause()  # UI event settle

            # permission.invite_list: enable and type "email".
            await pilot.click("#permission-invite Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"email")
            await pilot.pause()  # UI event settle

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # TagGrantEditWidget.on_mount calls list_tags()

            await pilot.click("#filter-name-value Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"env=prod")
            await pilot.pause()  # UI event settle

            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause()  # UI event settle
            await pilot.press("space")  # create=0
            await pilot.press("down")
            await pilot.press("space")  # read=1

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # BoundaryGrantEditWidget.on_mount calls list_boundaries()

            await pilot.click("#filter-name Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"zone1")
            await pilot.pause()  # UI event settle

            # SelectionList: create=0, read=1, update.name=2, ...
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause()  # UI event settle
            await pilot.press("space")  # create=0
            await pilot.press("down")
            await pilot.press("space")  # read=1
            await pilot.press("down")
            await pilot.press("space")  # update.name=2

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

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
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # TenantGrantEditWidget.on_mount calls list_tenants()

            # SelectionList: create=0, read=1, ...
            app.screen.query_one(textual.widgets.SelectionList).focus()
            await pilot.pause()  # UI event settle
            await pilot.press("down")  # move to read=1
            await pilot.press("space")  # toggle read

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["id"] is None
    assert grant["permission"]["read"] is True
    assert grant["permission"]["create"] is False


@pytest.mark.anyio
async def test_tui_ssh_grant_edit(api):
    """Edit an SSH shell grant: set filter.name, set username_list, enable permit_agent_forwarding."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)

        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        await auth.post(auth.directory.boundary, json={"name": "zone1"})
        role_id = await _setup_role_with_grant(auth, pf.tui.grant_edit.new_grant("ssh-shell"))

        app = pf.tui.app.TuiApp(auth)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount
            await pilot.press("down")  # navigate to test-role (row 1)
            await pilot.press("enter")  # open role view
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleViewScreen.on_mount
            await pilot.press("tab", "tab", "tab")  # focus grants DataTable
            await pilot.press("enter")
            await pilot.pause()  # screen transition
            await pilot.pause()  # SshShellGrantEditWidget.on_mount (3 APIs: identities, boundaries, bastions)

            await pilot.click("#filter-name Checkbox")
            await pilot.pause()  # UI event settle
            await pilot.press(*"root")
            await pilot.pause()  # UI event settle

            # username_list: click the input and type "alice"
            await pilot.click("#perm-username-list Input")
            await pilot.pause()  # UI event settle
            await pilot.press(*"alice")
            await pilot.pause()  # UI event settle

            await pilot.click("#perm-permit-agent-forwarding")

            await pilot.press("ctrl+s")  # confirm grant edits
            await _wait(pilot, app)  # action_edit_grant worker
            await pilot.press("ctrl+s")  # save role
            await _wait(pilot, app)  # action_save worker

        assert not [n for n in app._notifications if n.severity == "error"]

    grant = await _get_grant(auth, role_id)
    assert grant["filter"]["name"] == "root"
    assert grant["permission"]["username_list"] == ["alice"]
    assert grant["permission"]["permit_agent_forwarding"] is True
    assert grant["permission"]["permit_x11_forwarding"] is False


@pytest.mark.anyio
async def test_tui_tag_list(api):
    """Add a tag via the TUI, verify it exists, then delete it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down")  # navigate to Tag (index 4)
            await pilot.press("enter")  # open TagListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # TagListScreen.on_mount calls list_tags()

            await pilot.press("a")  # open add modal via action_add_tag worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _TagCreateScreen.on_mount (no API)
            await pilot.press(*"env")  # type name
            await pilot.press("tab")  # move to value input
            await pilot.press(*"prod")  # type value
            await pilot.press("enter")  # submit
            await _wait(pilot, app)  # action_add_tag worker posts tag

        assert not [n for n in app._notifications if n.severity == "error"]

    tags = await auth.list_tags()
    assert any(t["name"] == "env" and t["value"] == "prod" for t in tags)


@pytest.mark.anyio
async def test_tui_tag_delete(api):
    """Delete a tag via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down")  # navigate to Tag (index 4)
            await pilot.press("enter")  # open TagListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # TagListScreen.on_mount

            await pilot.press("d")  # delete row 0 via action_delete_tag worker
            await _wait(pilot, app)  # action_delete_tag worker deletes tag

        assert not [n for n in app._notifications if n.severity == "error"]

    tags = await auth.list_tags()
    assert not any(t["name"] == "env" and t["value"] == "prod" for t in tags)


@pytest.mark.anyio
async def test_tui_boundary_list(api):
    """Add a boundary via the TUI, verify it exists, then delete it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down")  # navigate to Boundary (index 3)
            await pilot.press("enter")  # open BoundaryListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BoundaryListScreen.on_mount calls list_boundaries()

            await pilot.press("a")  # open add modal via action_add_boundary worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _BoundaryCreateScreen.on_mount (no API)
            await pilot.press(*"zone1")  # type name
            await pilot.press("enter")  # submit (description is optional)
            await _wait(pilot, app)  # action_add_boundary worker posts boundary

        assert not [n for n in app._notifications if n.severity == "error"]

    boundaries = await auth.list_boundaries()
    assert any(b["name"] == "zone1" for b in boundaries)


@pytest.mark.anyio
async def test_tui_boundary_delete(api):
    """Delete a boundary via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.boundary, json={"name": "zone1", "description": ""})
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down")  # navigate to Boundary (index 3)
            await pilot.press("enter")  # open BoundaryListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BoundaryListScreen.on_mount

            # initialize creates a root boundary at row 0; zone1 is at row 1
            await pilot.press("down")
            await pilot.press("d")  # delete zone1 via action_delete_boundary worker
            await _wait(pilot, app)  # action_delete_boundary worker deletes boundary

        assert not [n for n in app._notifications if n.severity == "error"]

    boundaries = await auth.list_boundaries()
    assert not any(b["name"] == "zone1" for b in boundaries)


@pytest.mark.anyio
async def test_tui_bastion_list(api):
    """Add a bastion via the TUI and verify it exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down")  # navigate to Bastions (index 2)
            await pilot.press("enter")  # open BastionListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BastionListScreen.on_mount calls list_bastions()

            await pilot.press("a")  # open add modal via action_add_bastion worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _BastionCreateScreen.on_mount (no API)
            await pilot.press(*"https://register.example.com")  # type register_url
            await pilot.press("tab")  # move to connect_url
            await pilot.press(*"ssh://bastion.example.com")  # type connect_url
            await pilot.press("tab")  # move to ssh_proxy_jump
            await pilot.press(*"proxy.example.com")  # type ssh_proxy_jump
            await pilot.press("enter")  # submit
            await _wait(pilot, app)  # action_add_bastion worker posts bastion

        assert not [n for n in app._notifications if n.severity == "error"]

    bastions = await auth.list_bastions()
    assert any(b["register_url"] == "https://register.example.com" for b in bastions)


@pytest.mark.anyio
async def test_tui_bastion_delete(api):
    """Delete a bastion via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        response = await auth.post(
            auth.directory.bastion,
            json={
                "register_url": "https://register.example.com",
                "connect_url": "ssh://bastion.example.com",
                "ssh_proxy_jump": "proxy.example.com",
                "tag_id_list": [],
                "tag_name_value_list": [],
            },
        )
        bastion_id = response.json()["id"]
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down")  # navigate to Bastions (index 2)
            await pilot.press("enter")  # open BastionListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BastionListScreen.on_mount

            await pilot.press("d")  # delete row 0 via action_delete_bastion worker
            await _wait(pilot, app)  # action_delete_bastion worker deletes bastion

        assert not [n for n in app._notifications if n.severity == "error"]

    bastions = await auth.list_bastions()
    assert not any(b["id"] == bastion_id for b in bastions)


@pytest.mark.anyio
async def test_tui_bastion_add_tag(api):
    """Add a tag to a bastion via BastionViewScreen and save."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})

        response = await auth.post(
            auth.directory.bastion,
            json={
                "register_url": "https://register.example.com",
                "connect_url": None,
                "ssh_proxy_jump": None,
                "tag_id_list": [],
                "tag_name_value_list": [],
            },
        )
        bastion_id = response.json()["id"]

        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down")  # navigate to Bastions (index 2)
            await pilot.press("enter")  # open BastionListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BastionListScreen.on_mount

            await pilot.press("enter")  # open bastion's BastionViewScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BastionViewScreen.on_mount (no API)

            # BastionViewScreen: Input#register_url is focused; tab to #ssh_proxy_jump, then to #tags
            await pilot.press("tab", "tab", "tab")
            await pilot.press("a")  # action_add_tag → _TagAddScreen opens via worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _TagAddScreen.on_mount calls list_tags()

            await pilot.press(*"env=prod")  # type exact tag label
            await pilot.press("enter")  # submit; _TagAddScreen dismisses with tag dict
            await _wait(pilot, app)  # action_add_tag worker completes

            await pilot.press("ctrl+s")  # save bastion
            await _wait(pilot, app)  # action_save worker posts bastion

        assert not [n for n in app._notifications if n.severity == "error"]

    response = await auth.get(auth.directory.bastion, params={"id": bastion_id})
    bastion = response.json()["bastions"][0]
    assert any(t["name"] == "env" and t["value"] == "prod" for t in bastion["tag_list"])


@pytest.mark.anyio
async def test_tui_identity_list(api):
    """Add an identity via the TUI and verify it exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down")  # navigate to Identities (index 1)
            await pilot.press("enter")  # open IdentityListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityListScreen.on_mount calls list_identities()

            await pilot.press("a")  # open add modal via action_add_identity worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _IdentityCreateScreen.on_mount (no API)
            await pilot.press(*"alice")  # type name
            await pilot.press("enter")  # submit
            await _wait(pilot, app)  # action_add_identity worker posts identity

        assert not [n for n in app._notifications if n.severity == "error"]

    identities = await auth.list_identities()
    assert any(i["name"] == "alice" for i in identities)


@pytest.mark.anyio
async def test_tui_tenant_list(api):
    """Add a tenant via the TUI and verify it exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("enter")  # open TenantListScreen (index 0, no down needed)
            await pilot.pause()  # screen transition
            await pilot.pause()  # TenantListScreen.on_mount calls list_tenants()

            await pilot.press("a")  # open add modal via action_add_tenant worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _TenantCreateScreen.on_mount (no API)
            await pilot.press(*"acme")  # type name
            await pilot.press("tab")  # move to display_name input
            await pilot.press(*"Acme Corp")  # type display name
            await pilot.press("enter")  # submit
            await _wait(pilot, app)  # action_add_tenant worker posts tenant

        assert not [n for n in app._notifications if n.severity == "error"]

    tenants = await auth.list_tenants()
    assert any(t["name"] == "acme" and t["display_name"] == "Acme Corp" for t in tenants)


@pytest.mark.anyio
async def test_tui_role_delete(api):
    """Delete a role via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.role, json={"name": "to-delete"})
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down", "down", "down")  # navigate to Roles (index 4)
            await pilot.press("enter")  # open RoleListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # RoleListScreen.on_mount

            # role list: root=row0, to-delete=row1
            await pilot.press("down")
            await pilot.press("d")  # delete to-delete via action_delete_role worker
            await _wait(pilot, app)  # action_delete_role worker deletes role

        assert not [n for n in app._notifications if n.severity == "error"]

    roles = await auth.list_roles()
    assert not any(r["name"] == "to-delete" for r in roles)


@pytest.mark.anyio
async def test_tui_identity_delete(api):
    """Delete an identity via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(
            auth.directory.identity,
            json={
                "name": "alice",
                "boundary_id_list": [],
                "boundary_name_list": [],
                "tag_id_list": [],
                "tag_name_value_list": [],
            },
        )
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down")  # navigate to Identities (index 1)
            await pilot.press("enter")  # open IdentityListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityListScreen.on_mount

            # identity list: root=row0, alice=row1
            await pilot.press("down")
            await pilot.press("d")  # delete alice via action_delete_identity worker
            await _wait(pilot, app)  # action_delete_identity worker deletes identity

        assert not [n for n in app._notifications if n.severity == "error"]

    identities = await auth.list_identities()
    assert not any(i["name"] == "alice" for i in identities)


@pytest.mark.anyio
async def test_tui_tenant_delete(api):
    """Delete a tenant via the TUI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.tenant, json={"name": "acme", "display_name": "Acme Corp"})
        tenants_before = await auth.list_tenants()
        tenant_id = next(t["id"] for t in tenants_before if t["name"] == "acme")
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("enter")  # open TenantListScreen (index 0, no down needed)
            await pilot.pause()  # screen transition
            await pilot.pause()  # TenantListScreen.on_mount

            await pilot.press("d")  # delete row 0 via action_delete_tenant worker
            await _wait(pilot, app)  # action_delete_tenant worker deletes tenant

        assert not [n for n in app._notifications if n.severity == "error"]

        # verify deletion: direct GET for the specific tenant returns 404
        check = await auth.get(auth.directory.tenant, params={"id": tenant_id})
        assert check.status_code == 404


@pytest.mark.anyio
async def test_tui_boundary_edit_description(api):
    """Edit a boundary's description via BoundaryViewScreen and save."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        response = await auth.post(auth.directory.boundary, json={"name": "zone1"})
        boundary_id = response.json()["boundary"]["id"]
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down", "down", "down")  # navigate to Boundary (index 3)
            await pilot.press("enter")  # open BoundaryListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BoundaryListScreen.on_mount

            # boundary list: root=row0, zone1=row1
            await pilot.press("down")
            await pilot.press("enter")  # open zone1 BoundaryViewScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # BoundaryViewScreen.on_mount (no API)

            # BoundaryViewScreen: Input#name is focused; tab to Input#description
            await pilot.press("tab")
            await pilot.press(*"A test boundary")

            await pilot.press("ctrl+s")
            await _wait(pilot, app)  # action_save worker patches boundary

        assert not [n for n in app._notifications if n.severity == "error"]

    response = await auth.get(auth.directory.boundary, params={"id": boundary_id})
    boundary = response.json()["boundaries"][0]
    assert boundary["description"] == "A test boundary"


@pytest.mark.anyio
async def test_tui_identity_add_tag(api):
    """Add a tag to an identity via IdentityViewScreen and save."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        await auth.post(auth.directory.tag, json={"name": "env", "value": "prod"})

        # create a non-root identity so we can PATCH it (patching self is not allowed)
        response = await auth.post(
            auth.directory.identity,
            json={
                "name": "alice",
                "boundary_id_list": [],
                "boundary_name_list": [],
                "tag_id_list": [],
                "tag_name_value_list": [],
            },
        )
        alice_id = response.json()["id"]

        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()  # app startup
            await pilot.press("down")  # navigate to Identities (index 1)
            await pilot.press("enter")  # open IdentityListScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityListScreen.on_mount

            # identity list: root=row0, alice=row1
            await pilot.press("down")
            await pilot.press("enter")  # open alice's IdentityViewScreen
            await pilot.pause()  # screen transition
            await pilot.pause()  # IdentityViewScreen.on_mount (no API)

            # IdentityViewScreen: Input#name is focused; tab to ListView#tags
            # (action_add_tag requires #tags to have focus)
            await pilot.press("tab")
            await pilot.press("a")  # action_add_tag → _TagAddScreen opens via worker
            await pilot.pause()  # screen transition
            await pilot.pause()  # _TagAddScreen.on_mount calls list_tags()

            await pilot.press(*"env=prod")  # type exact tag label
            await pilot.press("enter")  # submit; _TagAddScreen dismisses with tag dict
            await _wait(pilot, app)  # action_add_tag worker completes

            await pilot.press("ctrl+s")  # save identity
            await _wait(pilot, app)  # action_save worker patches identity

        assert not [n for n in app._notifications if n.severity == "error"]

    response = await auth.get(auth.directory.identity, params={"id": alice_id})
    identity = response.json()["identities"][0]
    assert any(t["name"] == "env" and t["value"] == "prod" for t in identity["tags"])
