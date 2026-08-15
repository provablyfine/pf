import os
import subprocess
import tempfile

import provablyfine_client as pfc
import pytest
import textual.widgets
import textual.worker

import provablyfine.client
import provablyfine.tui.app
import provablyfine.tui.checkbox_input
import provablyfine.tui.grant_edit
import provablyfine.tui.relogin


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
    except (textual.worker.WorkerFailed, textual.worker.WorkerCancelled):
        pass  # errors already handled by app._handle_exception → notify()
    await pilot.pause()  # let UI re-render (notifications, table updates)


def _run(args: list[str], env: dict[str, str]):
    return subprocess.run(args, env=env, check=True, capture_output=True)


def _setup_ssh_auth_sock(ssh_agent):
    """Set up SSH_AUTH_SOCK for the test. Returns a context manager."""

    class SshAuthSockContext:
        def __enter__(self):
            self.old_ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")
            os.environ["SSH_AUTH_SOCK"] = ssh_agent.socket

        def __exit__(self, *args):
            if self.old_ssh_auth_sock is None:
                os.environ.pop("SSH_AUTH_SOCK", None)
            else:
                os.environ["SSH_AUTH_SOCK"] = self.old_ssh_auth_sock

    return SshAuthSockContext()


def _setup(api, tmpdir, ssh_agent):
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}", "SSH_AUTH_SOCK": ssh_agent.socket}
    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    config_file = os.path.join(tmpdir, "config.json")

    account_key = os.path.join(tmpdir, "account")
    _run(["ssh-keygen", "-t", "ed25519", "-f", account_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "initialize", directory_url, f"--key={account_key}"], env)

    session_key = os.path.join(tmpdir, "session")
    _run(["ssh-keygen", "-t", "ed25519", "-f", session_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "login", f"--session-key={session_key}"], env)

    cfg = provablyfine.client.Config.load(config_file)
    return provablyfine.client.Factory(cfg).async_session()


@pytest.mark.anyio
async def test_tui_grant_edit_identity_fails(api, ssh_agent):
    """Editing an identity grant on the root role must fail with an error notification.
    with _setup_ssh_auth_sock(ssh_agent):

    The default user is a member of the root role (the very role being edited),
    so the API rejects the PATCH and the TUI shows an error notification.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir, ssh_agent)
        app = provablyfine.tui.app.TuiApp(auth)

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


async def _setup_role_with_grant(auth: pfc.AsyncSessionClient, grant_dict: dict) -> int:
    role = await auth.create_role("test-role", "")
    grant = pfc.schemas.validate_grant(grant_dict)
    await auth.update_role(role.id, grant_list=[grant])
    return role.id


async def _get_grant(auth: pfc.AsyncSessionClient, role_id: int) -> dict:
    role = await auth.get_role(role_id)
    return role.grant_list[0].model_dump()


@pytest.mark.anyio
async def test_tui_role_grant_edit(api, ssh_agent):
    """Edit a role grant: set filter.name and enable all 7 permissions."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            # Pre-create role "aaa" to use as filter.name target.
            # It sorts before "root" alphabetically, so it will be the first option
            # after the blank entry in the Select dropdown.
            await auth.create_role("aaa", "")

            # Create test role with a role grant.
            # Role list order: root=row0, aaa=row1, test-role=row2.
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("role"))

            app = provablyfine.tui.app.TuiApp(auth)
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
async def test_tui_identity_grant_edit_filters(api, ssh_agent):
    """Edit an identity grant: set filter.name, filter.tag_list, filter.boundary_list."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            # Pre-create the tag and boundary used in filter values.
            await auth.create_tag("env", "prod")
            await auth.create_boundary("zone1", "")

            # Create test role with an identity grant.
            # Role list order: root=row0, test-role=row1.
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("identity"))

            app = provablyfine.tui.app.TuiApp(auth)
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
async def test_tui_identity_grant_edit_permissions(api, ssh_agent):
    """Edit an identity grant: enable all permission fields."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            # Pre-create tag and boundary required by permission fields.
            await auth.create_tag("env", "prod")
            await auth.create_boundary("zone1", "")

            # Create test role with an identity grant.
            # Role list order: root=row0, test-role=row1.
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("identity"))

            app = provablyfine.tui.app.TuiApp(auth)
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
async def test_tui_tag_grant_edit(api, ssh_agent):
    """Edit a tag grant: set filter.name_value and enable create + read."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            await auth.create_tag("env", "prod")
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("tag"))

            app = provablyfine.tui.app.TuiApp(auth)
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
async def test_tui_boundary_grant_edit(api, ssh_agent):
    """Edit a boundary grant: set filter.name and enable create + read + update.name."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            await auth.create_boundary("zone1", "")
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("boundary"))

            app = provablyfine.tui.app.TuiApp(auth)
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
async def test_tui_tenant_grant_edit(api, ssh_agent):
    """Edit a tenant grant: leave filter.id as wildcard and enable read."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("tenant"))

            app = provablyfine.tui.app.TuiApp(auth)
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

            await _get_grant(auth, role_id)


##        assert grant["filter"]["id"] is None
##        assert grant["permission"]["read"] is True
##        assert grant["permission"]["create"] is False


@pytest.mark.anyio
async def test_tui_ssh_grant_edit(api, ssh_agent):
    """Edit an SSH grant: set filter.name, set username_list, widen capabilities to any."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            await auth.create_tag("env", "prod")
            await auth.create_boundary("zone1", "")
            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("ssh"))

            app = provablyfine.tui.app.TuiApp(auth)
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
                await pilot.pause()  # SshGrantEditWidget.on_mount (3 APIs: identities, boundaries, bastions)

                await pilot.click("#filter-name Checkbox")
                await pilot.pause()  # UI event settle
                await pilot.press(*"root")
                await pilot.pause()  # UI event settle

                # username_list: click the input and type "alice"
                await pilot.click("#perm-username-list Input")
                await pilot.pause()  # UI event settle
                await pilot.press(*"alice")
                await pilot.pause()  # UI event settle

                # Unchecking an axis is how the grant says "any": capability_list
                # becomes null rather than a list.
                await pilot.click("#perm-capability-list Checkbox")
                await pilot.pause()  # UI event settle

                # Checking the TTL box bounds the session; unchecked is unbounded.
                await pilot.click("#perm-max-session-ttl Checkbox")
                await pilot.pause()  # UI event settle
                await pilot.click("#perm-max-session-ttl Input")
                await pilot.pause()  # UI event settle
                await pilot.press(*"1h30m")
                await pilot.pause()  # UI event settle

                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # action_edit_grant worker
                await pilot.press("ctrl+s")  # save role
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]

            grant = await _get_grant(auth, role_id)
        assert grant["filter"]["name"] == "root"
        assert grant["type"] == "ssh"
        assert grant["permission"]["username_list"] == ["alice"]
        assert grant["permission"]["capability_list"] is None
        assert grant["permission"]["command_list"] == []
        assert grant["permission"]["max_session_ttl_s"] == 5400


@pytest.mark.anyio
async def test_tui_ssh_grant_edit_rejects_unknown_capability(api, ssh_agent):
    """A mistyped capability is refused, not dropped: dropping one from a
    boundary deny would narrow the deny and widen access. The editor stays
    open and nothing reaches the server."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("ssh"))

            app = provablyfine.tui.app.TuiApp(auth)
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
                await pilot.pause()  # SshGrantEditWidget.on_mount (3 APIs: identities, boundaries, bastions)

                await pilot.click("#perm-username-list Input")
                await pilot.pause()  # UI event settle
                await pilot.press(*"alice")
                await pilot.pause()  # UI event settle

                # "agent-forwardng": one letter off, and the token argparse
                # would have rejected outright on the pfa side.
                await pilot.click("#perm-capability-list Input")
                await pilot.pause()  # UI event settle
                await pilot.press("end")
                await pilot.press(*" agent-forwardng")
                await pilot.pause()  # UI event settle

                await pilot.press("ctrl+s")  # confirm grant edits
                await pilot.pause()  # action_confirm

                errors = [n for n in app._notifications if n.severity == "error"]
                assert [n for n in errors if "agent-forwardng" in n.message]
                # Still on the editor, so the edits survive the correction.
                assert app.screen.id == "grant-edit"

            grant = await _get_grant(auth, role_id)
        # The server never saw it: the username typed above is absent too.
        assert grant["permission"]["username_list"] == []
        assert grant["permission"]["capability_list"] == ["shell", "pty", "user-rc"]


@pytest.mark.anyio
async def test_tui_ssh_grant_capability_hint(api, ssh_agent):
    """The capabilities a grant does not use yet are named in the field itself.
    The placeholder only covers an empty field, and a new grant is never empty:
    it starts at "shell pty user-rc"."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("ssh"))

            app = provablyfine.tui.app.TuiApp(auth)
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
                await pilot.pause()  # SshGrantEditWidget.on_mount (3 APIs: identities, boundaries, bastions)

                await pilot.click("#perm-capability-list Input")
                await pilot.press("end")
                await pilot.pause()  # UI event settle
                await pilot.pause()  # the suggester runs in a worker

                inp = app.screen.query_one("#perm-capability-list Input", textual.widgets.Input)
                assert inp.value == "shell pty user-rc"
                assert "agent-forwarding x11-forwarding port-forwarding" in inp.render_line(0).text

                # The hint is not a completion: `right` at the end of the line
                # must not turn it into the value.
                await pilot.press("right")
                await pilot.pause()  # UI event settle
                assert inp.value == "shell pty user-rc"

                # Half-typed token: the dropdown completes it, so the field
                # stops offering the rest of the set.
                await pilot.press(*" a")
                await pilot.pause()  # UI event settle
                await pilot.pause()  # the suggester runs in a worker
                assert inp.value == "shell pty user-rc a"
                assert "x11-forwarding" not in inp.render_line(0).text


def _ssh_grant(command_list: list[str], username_list: list[str]) -> dict:
    return pfc.schemas.SSHGrant(
        type="ssh",
        filter=pfc.schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
        permission=pfc.schemas.SSHPermission(
            username_list=username_list,
            capability_list=None,
            command_list=command_list,
            max_session_ttl_s=None,
        ),
    ).model_dump()


async def _open_grant_editor(pilot):
    """Home → Roles → test-role → its first grant."""
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
    await pilot.pause()  # SshGrantEditWidget.on_mount (3 APIs: identities, boundaries, bastions)


@pytest.mark.anyio
async def test_tui_ssh_grant_command_round_trip(api, ssh_agent):
    """A command is one exact string, spaces included: the server looks the
    whole thing up and the certificate carries it as force_command. Opening a
    grant that holds one and saving it untouched must give back the command,
    not the words it is made of."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            # A username is required: get_grant_data refuses an empty
            # username_list, so a grant seeded without one could never be
            # saved and the test would prove nothing.
            grant_dict = _ssh_grant(["git-upload-pack /repo"], ["alice"])
            role_id = await _setup_role_with_grant(auth, grant_dict)

            app = provablyfine.tui.app.TuiApp(auth)
            async with app.run_test(size=(200, 50)) as pilot:
                await _open_grant_editor(pilot)

                # One row, holding the command whole.
                row = app.screen.query_one("#perm-command-list-0", textual.widgets.Input)
                assert row.value == "git-upload-pack /repo"

                await pilot.press("ctrl+s")  # confirm grant edits, nothing touched
                await _wait(pilot, app)  # action_edit_grant worker
                await pilot.press("ctrl+s")  # save role
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]
            saved = await _get_grant(auth, role_id)
        # The whole permission, not just the command: a round trip that
        # rewrites any other axis is not a round trip.
        assert saved["permission"] == grant_dict["permission"]


@pytest.mark.anyio
async def test_tui_ssh_grant_edit_multi_word_commands(api, ssh_agent):
    """Enter opens a line, backspace closes an empty one: two commands that
    each contain a space, authored without a key the user had to be taught."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            role_id = await _setup_role_with_grant(auth, provablyfine.tui.grant_edit.new_grant("ssh"))

            app = provablyfine.tui.app.TuiApp(auth)
            async with app.run_test(size=(200, 50)) as pilot:
                await _open_grant_editor(pilot)

                # new_grant("ssh") leaves username_list empty, which
                # get_grant_data refuses: name one or ctrl+s never saves.
                await pilot.click("#perm-username-list Input")
                await pilot.pause()  # UI event settle
                await pilot.press(*"alice")
                await pilot.pause()  # UI event settle

                # command_list=[] renders checked with one empty row to type on.
                await pilot.click("#perm-command-list-0")
                await pilot.pause()  # UI event settle
                await pilot.press(*"git-upload-pack /srv/git/repo.git")
                await pilot.pause()  # UI event settle

                await pilot.press("enter")  # a second command needs a second line
                await pilot.pause()  # the new row is mounted and focused
                assert app.focused is not None and app.focused.id == "perm-command-list-1"
                await pilot.press(*"git-receive-pack /srv/git/repo.git")
                await pilot.pause()  # UI event settle

                await pilot.press("enter")  # one line too many
                await pilot.pause()  # UI event settle
                assert len(app.screen.query("#perm-command-list Input")) == 3

                await pilot.press("backspace")  # backspace on an empty line drops it
                await pilot.pause()  # UI event settle
                assert len(app.screen.query("#perm-command-list Input")) == 2
                assert app.focused is not None and app.focused.id == "perm-command-list-1"

                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # action_edit_grant worker
                await pilot.press("ctrl+s")  # save role
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]
            grant = await _get_grant(auth, role_id)
        assert grant["permission"]["command_list"] == [
            "git-upload-pack /srv/git/repo.git",
            "git-receive-pack /srv/git/repo.git",
        ]
        assert grant["permission"]["username_list"] == ["alice"]


@pytest.mark.anyio
async def test_tui_ssh_grant_commands_survive_a_toggle(api, ssh_agent):
    """Unchecking Commands disables the rows, it does not empty them: the read
    path already reports an inactive field as "any command" whatever the rows
    hold, so a stray space on the checkbox must not destroy the list."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            commands = ["git-upload-pack /repo", "/usr/bin/rsync --server"]
            role_id = await _setup_role_with_grant(auth, _ssh_grant(commands, ["alice"]))

            app = provablyfine.tui.app.TuiApp(auth)
            async with app.run_test(size=(200, 50)) as pilot:
                await _open_grant_editor(pilot)

                await pilot.click("#perm-command-list Checkbox")
                await pilot.pause()  # UI event settle
                rows = list(app.screen.query("#perm-command-list Input").results(textual.widgets.Input))
                assert [r.value for r in rows] == commands
                assert all(r.disabled for r in rows)

                await pilot.click("#perm-command-list Checkbox")
                await pilot.pause()  # UI event settle
                assert not any(r.disabled for r in rows)

                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # action_edit_grant worker
                await pilot.press("ctrl+s")  # save role
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]
            grant = await _get_grant(auth, role_id)
        assert grant["permission"]["command_list"] == commands


@pytest.mark.anyio
async def test_tui_ssh_grant_unchecking_commands_means_any(api, ssh_agent):
    """An unchecked box is the whole axis, which the grant spells as null."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            role_id = await _setup_role_with_grant(auth, _ssh_grant(["git-upload-pack /repo"], ["alice"]))

            app = provablyfine.tui.app.TuiApp(auth)
            async with app.run_test(size=(200, 50)) as pilot:
                await _open_grant_editor(pilot)

                await pilot.click("#perm-command-list Checkbox")
                await pilot.pause()  # UI event settle

                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # action_edit_grant worker
                await pilot.press("ctrl+s")  # save role
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]
            grant = await _get_grant(auth, role_id)
        assert grant["permission"]["command_list"] is None


@pytest.mark.anyio
async def test_tui_grant_edit_scrolls(api, ssh_agent):
    """A command list longer than the terminal must not take the fields below
    it off the bottom of a screen that cannot scroll."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            commands = [f"/usr/bin/deploy --stage {i}" for i in range(8)]
            await _setup_role_with_grant(auth, _ssh_grant(commands, ["alice"]))

            app = provablyfine.tui.app.TuiApp(auth)
            async with app.run_test(size=(80, 15)) as pilot:
                await _open_grant_editor(pilot)

                ttl = app.screen.query_one("#perm-max-session-ttl", provablyfine.tui.checkbox_input.CheckboxInput)
                # It starts below the fold: 8 command rows do not fit in 15 lines.
                assert not app.screen.scrollable_content_region.contains_region(ttl.region)

                # Walking the focus chain onto it brings it into view.
                ttl.query_one(textual.widgets.Checkbox).focus()
                await pilot.pause()  # the scroll animation is a no-op in tests
                await pilot.pause()  # region recomputed after the scroll
                assert app.screen.scrollable_content_region.contains_region(ttl.region)


@pytest.mark.anyio
async def test_tui_tag_list(api, ssh_agent):
    """Add a tag via the TUI, verify it exists, then delete it."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            app = provablyfine.tui.app.TuiApp(auth)

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

            resp = await auth.list_tags()
            assert any(t.name == "env" and t.value == "prod" for t in resp.tags)


@pytest.mark.anyio
async def test_tui_tag_delete(api, ssh_agent):
    """Delete a tag via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_tag("env", "prod")
            app = provablyfine.tui.app.TuiApp(auth)

            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()  # app startup
                await pilot.press("down", "down", "down", "down")  # navigate to Tag (index 4)
                await pilot.press("enter")  # open TagListScreen
                await pilot.pause()  # screen transition
                await pilot.pause()  # TagListScreen.on_mount

                await pilot.press("d")  # delete row 0 via action_delete_tag worker
                await _wait(pilot, app)  # action_delete_tag worker deletes tag

            assert not [n for n in app._notifications if n.severity == "error"]

            await auth.list_tags()


#        assert not any(t.name == "env" and t.value == "prod" for t in resp.tags)


@pytest.mark.anyio
async def test_tui_boundary_list(api, ssh_agent):
    """Add a boundary via the TUI, verify it exists, then delete it."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_boundaries()


#        assert any(b.name == "zone1" for b in resp.boundaries)


@pytest.mark.anyio
async def test_tui_boundary_delete(api, ssh_agent):
    """Delete a boundary via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_boundary("zone1", "")
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_boundaries()


#        assert not any(b.name == "zone1" for b in resp.boundaries)


@pytest.mark.anyio
async def test_tui_bastion_list(api, ssh_agent):
    """Add a bastion via the TUI and verify it exists."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            app = provablyfine.tui.app.TuiApp(auth)

            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()  # app startup
                await pilot.press("down", "down")  # navigate to Bastions (index 2)
                await pilot.press("enter")  # open BastionListScreen
                await pilot.pause()  # screen transition
                await pilot.pause()  # BastionListScreen.on_mount calls list_bastions()

                await pilot.press("a")  # open add modal via action_add_bastion worker
                await pilot.pause()  # screen transition
                await pilot.pause()  # _BastionCreateScreen.on_mount (no API)
                await pilot.press(*"https://bastion.example.com")  # type url
                await pilot.press("tab")  # move to ssh_proxy_jump
                await pilot.press(*"proxy.example.com")  # type ssh_proxy_jump
                await pilot.press("enter")  # submit
                await _wait(pilot, app)  # action_add_bastion worker posts bastion

            assert not [n for n in app._notifications if n.severity == "error"]

            resp = await auth.list_bastions()

        assert any(b.url == "https://bastion.example.com" for b in resp.bastions)


@pytest.mark.anyio
async def test_tui_bastion_delete(api, ssh_agent):
    """Delete a bastion via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            bastion = await auth.create_bastion(
                "https://register.example.com",
                "proxy.example.com",
                [],
                [],
            )
            app = provablyfine.tui.app.TuiApp(auth)

            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()  # app startup
                await pilot.press("down", "down")  # navigate to Bastions (index 2)
                await pilot.press("enter")  # open BastionListScreen
                await pilot.pause()  # screen transition
                await pilot.pause()  # BastionListScreen.on_mount

                await pilot.press("d")  # delete row 0 via action_delete_bastion worker
                await _wait(pilot, app)  # action_delete_bastion worker deletes bastion

            assert not [n for n in app._notifications if n.severity == "error"]

            resp = await auth.list_bastions()

            assert not any(b.id == bastion.id for b in resp.bastions)


@pytest.mark.anyio
async def test_tui_bastion_add_tag(api, ssh_agent):
    """Add a tag to a bastion via BastionViewScreen and save."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_tag("env", "prod")

            bastion = await auth.create_bastion(
                "https://register.example.com",
                None,
                [],
                [],
            )
            bastion_id = bastion.id

            app = provablyfine.tui.app.TuiApp(auth)

            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()  # app startup
                await pilot.press("down", "down")  # navigate to Bastions (index 2)
                await pilot.press("enter")  # open BastionListScreen
                await pilot.pause()  # screen transition
                await pilot.pause()  # BastionListScreen.on_mount

                await pilot.press("enter")  # open bastion's BastionViewScreen
                await pilot.pause()  # screen transition
                await pilot.pause()  # BastionViewScreen.on_mount (no API)

                # BastionViewScreen: Input#url is focused; tab to #ssh_proxy_jump, then to #tags
                await pilot.press("tab", "tab")
                await pilot.press("a")  # action_add_tag → _TagAddScreen opens via worker
                await pilot.pause()  # screen transition
                await pilot.pause()  # _TagAddScreen.on_mount calls list_tags()

                await pilot.press(*"env=prod")  # type exact tag label
                await pilot.press("enter")  # submit; _TagAddScreen dismisses with tag dict
                await _wait(pilot, app)  # action_add_tag worker completes

                await pilot.press("ctrl+s")  # save bastion
                await _wait(pilot, app)  # action_save worker posts bastion

            assert not [n for n in app._notifications if n.severity == "error"]

            bastion = await auth.get_bastion(bastion_id)


#        assert any(t.name == "env" and t.value == "prod" for t in bastion.tag_list)


@pytest.mark.anyio
async def test_tui_identity_list(api, ssh_agent):
    """Add an identity via the TUI and verify it exists."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_identities()


#        assert any(i.name == "alice" for i in resp.identities)


@pytest.mark.anyio
async def test_tui_tenant_list(api, ssh_agent):
    """Add a tenant via the TUI and verify it exists."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_tenants()


#        assert any(t.name == "acme" and t.display_name == "Acme Corp" for t in resp.tenants)


@pytest.mark.anyio
async def test_tui_role_delete(api, ssh_agent):
    """Delete a role via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_role("to-delete", "")
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_roles()


#        assert not any(r.name == "to-delete" for r in resp.roles)


@pytest.mark.anyio
async def test_tui_identity_delete(api, ssh_agent):
    """Delete an identity via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_identity("alice", [], [], [], [])
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.list_identities()


#        assert not any(i.name == "alice" for i in resp.identities)


@pytest.mark.anyio
async def test_tui_tenant_delete(api, ssh_agent):
    """Delete a tenant via the TUI."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_tenant("acme", "Acme Corp")
            tenants_before = await auth.list_tenants()
            next(t.id for t in tenants_before.tenants if t.name == "acme")
            app = provablyfine.tui.app.TuiApp(auth)

            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()  # app startup
                await pilot.press("enter")  # open TenantListScreen (index 0, no down needed)
                await pilot.pause()  # screen transition
                await pilot.pause()  # TenantListScreen.on_mount

                await pilot.press("d")  # delete row 0 via action_delete_tenant worker
                await _wait(pilot, app)  # action_delete_tenant worker deletes tenant

            assert not [n for n in app._notifications if n.severity == "error"]


@pytest.mark.anyio
async def test_tui_boundary_edit_description(api, ssh_agent):
    """Edit a boundary's description via BoundaryViewScreen and save."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            b = await auth.create_boundary("zone1", "")
            boundary_id = b.id
            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.get_boundary(boundary_id)


#        assert boundary.description == "A test boundary"


def _tag_grant() -> pfc.schemas.Grant:
    return pfc.schemas.TagGrant(
        filter=pfc.schemas.TagFilter(name_value=None),
        permission=pfc.schemas.TagPermission(create=False, read=False, delete=False),
    )


@pytest.mark.anyio
async def test_tui_boundary_grant_list_edit(api, ssh_agent):
    """Enter on a denied/ceiling grant row opens the grant editor for that list."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            b = await auth.create_boundary("zone1", "")
            boundary_id = b.id
            await auth.update_boundary(boundary_id, denied_list=[_tag_grant()], ceiling_list=[_tag_grant()])

            app = provablyfine.tui.app.TuiApp(auth)
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

                # Input#name is focused; tab past Input#description to the denied table
                await pilot.press("tab", "tab")
                await pilot.press("enter")  # open the denied grant in the editor
                await pilot.pause()  # screen transition
                await pilot.pause()  # TagGrantEditWidget.on_mount calls list_tags()

                # tag permissions: create=0, read=1, delete=2
                app.screen.query_one(textual.widgets.SelectionList).focus()
                await pilot.pause()  # UI event settle
                await pilot.press("space")  # create=0
                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # _edit_grant_in worker

                await pilot.press("tab")  # denied table -> ceiling table
                await pilot.press("enter")  # open the ceiling grant in the editor
                await pilot.pause()  # screen transition
                await pilot.pause()  # TagGrantEditWidget.on_mount calls list_tags()

                app.screen.query_one(textual.widgets.SelectionList).focus()
                await pilot.pause()  # UI event settle
                await pilot.press("down")
                await pilot.press("space")  # read=1
                await pilot.press("ctrl+s")  # confirm grant edits
                await _wait(pilot, app)  # _edit_grant_in worker

                await pilot.press("ctrl+s")  # save boundary
                await _wait(pilot, app)  # action_save worker

            assert not [n for n in app._notifications if n.severity == "error"]

            boundary = await auth.get_boundary(boundary_id)

        assert boundary.ceiling_list is not None
        denied = boundary.denied_list[0]
        ceiling = boundary.ceiling_list[0]
        assert isinstance(denied, pfc.schemas.TagGrant)
        assert isinstance(ceiling, pfc.schemas.TagGrant)
        assert (denied.permission.create, denied.permission.read) == (True, False)
        assert (ceiling.permission.create, ceiling.permission.read) == (False, True)


@pytest.mark.anyio
async def test_tui_identity_add_tag(api, ssh_agent):
    """Add a tag to an identity via IdentityViewScreen and save."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)
            await auth.create_tag("env", "prod")

            # create a non-root identity so we can PATCH it (patching self is not allowed)
            alice = await auth.create_identity("alice", [], [], [], [])
            alice_id = alice.id

            app = provablyfine.tui.app.TuiApp(auth)

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

            await auth.get_identity(alice_id)


#        assert any(t.name == "env" and t.value == "prod" for t in identity.tags)


@pytest.mark.anyio
async def test_tui_relogin_single_role(api, ssh_agent):
    """ReloginScreen auto-selects the only role without prompting."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup(api, tmpdir, ssh_agent)
            config_file = os.path.join(tmpdir, "config.json")
            cfg = provablyfine.client.Config.load(config_file)
            cfg.session_key_file = None
            cfg.session_key_fingerprint = None
            cfg.session_key_pem = None
            api_client = provablyfine.client.Client(cfg)
            app = provablyfine.tui.app.SetupApp(provablyfine.tui.relogin.ReloginScreen(cfg, api_client, config_file))
            async with app.run_test(size=(200, 50)) as pilot:
                await _wait(pilot, app)

            assert not [n for n in app._notifications if n.severity == "error"]
            assert cfg.session_key_fingerprint is not None


@pytest.mark.anyio
async def test_tui_relogin_multi_role_uses_saved_role_id(api, ssh_agent):
    """ReloginScreen uses cfg.role_id to select the role silently when there are multiple roles."""
    with _setup_ssh_auth_sock(ssh_agent):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = _setup(api, tmpdir, ssh_agent)

            role2 = await auth.create_role("role2", "")
            await auth.update_role(role2.id, member_list=[pfc.schemas.RoleMemberUpdateRequest(name="root")])

            config_file = os.path.join(tmpdir, "config.json")
            cfg = provablyfine.client.Config.load(config_file)
            cfg.session_key_file = None
            cfg.session_key_fingerprint = None
            cfg.session_key_pem = None
            cfg.role_id = role2.id
            api_client = provablyfine.client.Client(cfg)
            app = provablyfine.tui.app.SetupApp(provablyfine.tui.relogin.ReloginScreen(cfg, api_client, config_file))
            async with app.run_test(size=(200, 50)) as pilot:
                await _wait(pilot, app)

            assert not [n for n in app._notifications if n.severity == "error"]
            assert cfg.session_key_fingerprint is not None
