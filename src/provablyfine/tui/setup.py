import asyncio
import os
import typing
import urllib.parse

import provablyfine_client as pfc
import requests
import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client, ssh
from . import base, relogin


def _list_ssh_keys() -> list[tuple[str, str]]:
    """List SSH keys from agent and ~/.ssh. Returns list of (label, identifier) tuples."""
    keys: list[tuple[str, str]] = []
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            fp = identity.public_key.ssh_fingerprint()
            comment = identity.comment or fp
            keys.append((f"{fp} ({comment})", fp))
    except Exception:
        pass
    ssh_dir = os.path.expanduser("~/.ssh")
    for name in ("id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"):
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path):
            keys.append((name, path))
    return keys


class _KeySelectScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _KeySelectScreen {
        align: center middle;
    }
    _KeySelectScreen > VerticalGroup {
        width: 72;
        height: auto;
        background: $surface;
        border: thick $primary;
    }
    _KeySelectScreen ListView {
        height: auto;
        max-height: 10;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, keys: list[tuple[str, str]]) -> None:
        super().__init__()
        self._keys = keys

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Account Key"
            yield textual.widgets.ListView(
                *[textual.widgets.ListItem(textual.widgets.Label(label)) for label, _ in self._keys]
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self) -> None:
        index = self.query_one(textual.widgets.ListView).index
        if index is None or index >= len(self._keys):
            return
        self.dismiss(self._keys[index][1])


class _AuthMethodSelectScreen(textual.screen.ModalScreen[pfc.schemas.AuthPublicSummary | None]):
    DEFAULT_CSS = """
    _AuthMethodSelectScreen {
        align: center middle;
    }
    _AuthMethodSelectScreen > VerticalGroup {
        width: 40;
        height: auto;
        background: $surface;
        border: thick $primary;
    }
    _AuthMethodSelectScreen ListView {
        height: auto;
        max-height: 10;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, auths: list[pfc.schemas.AuthPublicSummary]) -> None:
        super().__init__()
        self._auths = auths

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Auth Method"
            yield textual.widgets.ListView(
                *[textual.widgets.ListItem(textual.widgets.Label(a.name)) for a in self._auths]
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self) -> None:
        index = self.query_one(textual.widgets.ListView).index
        if index is None or index >= len(self._auths):
            return
        self.dismiss(self._auths[index])


class SetupChoiceScreen(base.Screen):
    BINDINGS: typing.ClassVar = [("escape", "quit", "Quit")]
    DEFAULT_CSS = """
    SetupChoiceScreen ListView {
        border: solid $primary;
        width: 40;
        height: auto;
        margin: 1 2;
    }
    """

    def __init__(self, config_path: str) -> None:
        super().__init__()
        self._config_path = config_path

    def compose(self) -> textual.app.ComposeResult:
        lv = textual.widgets.ListView(
            textual.widgets.ListItem(textual.widgets.Label("New server")),
            textual.widgets.ListItem(textual.widgets.Label("Connect to existing server")),
        )
        lv.border_title = "Setup"
        yield lv
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def action_quit(self) -> None:
        self.app.exit()

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self) -> None:
        index = self.query_one(textual.widgets.ListView).index
        if index == 0:
            self.app.push_screen(NewServerSetupScreen(self._config_path))
        elif index == 1:
            self.app.push_screen(ConnectScreen(self._config_path))


class NewServerSetupScreen(base.Screen):
    BINDINGS: typing.ClassVar = [("escape", "app.pop_screen", "Back")]
    DEFAULT_CSS = """
    NewServerSetupScreen Input {
        border: solid $primary;
        margin: 1 2;
    }
    NewServerSetupScreen ListView {
        border: solid $primary;
        height: auto;
        max-height: 10;
        margin: 1 2;
    }
    NewServerSetupScreen #status {
        margin: 0 2;
    }
    """

    def __init__(self, config_path: str) -> None:
        super().__init__()
        self._config_path = config_path
        self._keys: list[tuple[str, str]] = []

    def compose(self) -> textual.app.ComposeResult:
        url_input = textual.widgets.Input(
            placeholder="https://example.com/pf/t/tenant/directory", id="url", compact=True
        )
        url_input.border_title = "Directory URL"
        yield url_input
        lv = textual.widgets.ListView(id="keys")
        lv.border_title = "Account Key"
        yield lv
        yield textual.widgets.Label("", id="status")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def on_mount(self) -> None:
        self._keys = _list_ssh_keys()
        lv = self.query_one("#keys", textual.widgets.ListView)
        for label, _ in self._keys:
            lv.append(textual.widgets.ListItem(textual.widgets.Label(label)))
        if not self._keys:
            self.query_one("#status", textual.widgets.Label).update("No SSH keys found in agent or ~/.ssh")
        else:
            self.query_one("#status", textual.widgets.Label).update("Enter URL then select account key")

    @textual.on(textual.widgets.ListView.Selected)
    def _on_key_selected(self) -> None:
        url = self.query_one("#url", textual.widgets.Input).value.strip()
        if not url:
            self.notify("Please enter a directory URL first", severity="warning")
            return
        index = self.query_one("#keys", textual.widgets.ListView).index
        if index is None or index >= len(self._keys):
            return
        _, account_key = self._keys[index]
        self._do_initialize(url, account_key)

    @textual.work(thread=True)
    def _do_initialize(self, url: str, account_key: str) -> None:
        def set_status(text: str) -> None:
            self.app.call_from_thread(lambda: self.query_one("#status", textual.widgets.Label).update(text))

        set_status("Connecting...")
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                raise pfc.exceptions.UI(f"Unable to read directory: {resp.status_code}")
            directory_data = resp.json()
            c = client.Config(directory_url=url, directory=directory_data)
            api = client.Client(c)

            set_status("Initializing...")
            try:
                f = client.Factory(c)
                f.invitation(f.public().initialize(), account_key).accept_invitation()
            except pfc.exceptions.UI as e:
                if "already initialized" in str(e):
                    raise pfc.exceptions.UI("Server already initialized — use 'Connect to existing server'")
                raise

            set_status("Logging in...")
            c.account_key = account_key
            c.auth_name = "default"
            fp = relogin.http_sig_login(c, api)
            c.session_key = fp
            c.save(self._config_path)
            self.app.call_from_thread(self.app.exit)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            set_status("Enter URL then select account key")


class ConnectScreen(base.Screen):
    BINDINGS: typing.ClassVar = [("escape", "app.pop_screen", "Back")]
    DEFAULT_CSS = """
    ConnectScreen Input {
        border: solid $primary;
        margin: 1 2;
    }
    ConnectScreen #status {
        margin: 0 2;
    }
    """

    def __init__(self, config_path: str) -> None:
        super().__init__()
        self._config_path = config_path

    def compose(self) -> textual.app.ComposeResult:
        url_input = textual.widgets.Input(
            placeholder="https://example.com/pf/t/tenant/directory?invitation=...&auth=...",
            id="url",
            compact=True,
        )
        url_input.border_title = "Server URL"
        yield url_input
        yield textual.widgets.Label("Paste invitation URL or directory URL", id="status")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        url = self.query_one("#url", textual.widgets.Input).value.strip()
        if url:
            self._handle_url(url)

    @textual.work
    async def _handle_url(self, url: str) -> None:
        status = self.query_one("#status", textual.widgets.Label)

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        clean_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment)
        )
        invitation = params.get("invitation", [None])[0]
        auth_name = params.get("auth", [None])[0]

        status.update("Connecting...")
        try:
            resp = await asyncio.to_thread(requests.get, clean_url, timeout=5)
        except Exception:
            self.notify("Unable to connect to server", severity="error")
            status.update("Paste invitation URL or directory URL")
            return
        if resp.status_code != 200:
            self.notify(f"Unable to read directory ({resp.status_code})", severity="error")
            status.update("Paste invitation URL or directory URL")
            return
        directory_data = resp.json()
        c = client.Config(directory_url=clean_url, directory=directory_data)
        api = client.Client(c)
        factory = client.Factory(c)

        account_key: str | None = None

        if invitation:
            keys = await asyncio.to_thread(_list_ssh_keys)
            if not keys:
                self.notify("No SSH keys found — cannot accept invitation", severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            account_key = await self.app.push_screen_wait(_KeySelectScreen(keys))
            if account_key is None:
                status.update("Paste invitation URL or directory URL")
                return

            status.update("Accepting invitation...")
            try:
                await asyncio.to_thread(factory.invitation(invitation, account_key).accept_invitation)
            except pfc.exceptions.UI as e:
                self.notify(str(e), severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            c.account_key = account_key

        if auth_name is None:
            status.update("Fetching auth methods...")
            try:
                auths = await factory.async_public().list_public_auths()
            except pfc.exceptions.UI as e:
                self.notify(str(e), severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            if len(auths) == 0:
                self.notify("No auth methods available", severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            selected = await self.app.push_screen_wait(_AuthMethodSelectScreen(auths))
            if selected is None:
                status.update("Paste invitation URL or directory URL")
                return
            auth_name = selected.name
            auth_type = selected.type
        else:
            try:
                auth_public = await factory.async_public().get_public_auth(auth_name)
                auth_type = auth_public.config.type
            except pfc.exceptions.UI as e:
                self.notify(str(e), severity="error")
                status.update("Paste invitation URL or directory URL")
                return
        c.auth_name = auth_name

        if auth_type == "http_sig" and account_key is None:
            keys = await asyncio.to_thread(_list_ssh_keys)
            if not keys:
                self.notify("No SSH keys found — cannot login", severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            account_key = await self.app.push_screen_wait(_KeySelectScreen(keys))
            if account_key is None:
                self.notify("No SSH key selected — cannot login", severity="error")
                status.update("Paste invitation URL or directory URL")
                return
            c.account_key = account_key

        status.update(f"Logging in via {auth_name}...")
        try:
            if auth_type == "http_sig":
                fp = await asyncio.to_thread(relogin.http_sig_login, c, api)
            else:
                self.notify(f"Opening browser for {auth_name}...")
                fp = await asyncio.to_thread(relogin.login, api, auth_name, auth_type)
            c.session_key = fp
            c.save(self._config_path)
            self.app.exit()
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            status.update("Paste invitation URL or directory URL")
