import dataclasses

from . import recorder


@dataclasses.dataclass(frozen=True)
class Step:
    keys: tuple[str, ...] = ()
    wait_for: str | None = None
    timeout: float = 5.0
    label: str | None = None


def run_scenario(rec: recorder.PtyRecorder, steps: list[Step]) -> None:
    for step in steps:
        if step.keys:
            rec.send(*step.keys)
        if step.wait_for is not None:
            rec.wait_for(step.wait_for, timeout=step.timeout)
        elif step.keys:
            # No text to confirm against (e.g. a plain focus-moving tab):
            # give the state transition time to land so it isn't racing the
            # next step's input.
            rec.idle(0.6)
        if step.label is not None:
            rec.mark(step.label)


# The app boots directly into the Identities list (nav_pane.NAV_GROUPS'
# first section) — there is no picker screen to land on first. A persistent
# nav pane sits top-left on every screen; `shift+tab` reaches it (it's
# always last in the screen's tab-focus chain) from wherever content focus
# currently is, then arrow keys move its cursor (group headings are
# disabled list items, skipped automatically) and `enter` switches section.
#
# Identities list -> identity detail -> back -> Action log list -> quit.
# Browse-only: no typing, no creation. Needs pre-seeded named identities and
# at least one audit log entry (the seeding calls themselves produce some).
QUICK_TOUR: list[Step] = [
    Step(wait_for="Unix username", label="Identities list"),
    Step(keys=("enter",), wait_for="Unix username", label="Identity detail"),  # IdentityViewScreen for row 0
    Step(keys=("escape",), wait_for="Unix username"),  # back to IdentityListScreen
    # Identities(0) -> Action log(7): nav pane cursor starts on Identities
    # (it always matches the active section), so this is a single relative
    # jump of 7, the same way the old tour did a single relative "down".
    Step(keys=("shift+tab", "down", "down", "down", "down", "down", "down", "down")),
    Step(keys=("enter",), wait_for="Time", label="Audit log"),  # AuditLogListScreen (column header)
    Step(keys=("ctrl+q",)),  # quit — a root section screen's own `escape` now just refocuses the nav pane
]


# Real login, then every resource section in the nav pane's group order,
# each one creating its own demo data live. Sections are visited in
# nav_pane.NAV_ITEMS order, so each one is reached from the previous by a
# single relative "down" on the nav pane (group headings don't consume a
# keypress: ListView skips disabled items automatically) — the same
# adjacency trick the old Home-based tour used.
THOROUGH_TOUR: list[Step] = [
    # Login (ReloginScreen -> auto http_sig login -> TuiApp boots into Identities)
    Step(wait_for="Reconnecting", timeout=10.0, label="Logging in"),
    Step(wait_for="Unix username", timeout=15.0, label="Identities"),
    # Identities: create, then invite (seeded throwaway secret)
    Step(keys=("a",), wait_for="Add an identity"),
    Step(
        keys=("dana", "enter"), wait_for="Unix username", timeout=8.0, label="Identity created"
    ),  # auto-opens IdentityViewScreen
    Step(keys=("escape",), wait_for="Invite", timeout=8.0),  # back to list (footer binding, unique to the list)
    Step(keys=("i",), wait_for="manual"),  # _InviteMethodScreen (border title truncates to "Invitatio…")
    Step(
        keys=("enter",), wait_for="Invitation secret", timeout=8.0, label="Inviting the identity"
    ),  # method "manual" (default)
    Step(keys=("escape",), wait_for="dana"),  # dismiss secret, back to list
    # Tags
    Step(keys=("shift+tab", "down", "enter"), wait_for="Value", timeout=8.0, label="Tags"),
    Step(keys=("a",), wait_for="Add a tag"),
    Step(keys=("env", "tab", "demo", "enter"), wait_for="env", timeout=8.0, label="Tag created"),
    # Roles: create, add two grant types to the (popup) grant editor
    Step(keys=("shift+tab", "down", "enter"), wait_for="Members", timeout=8.0, label="Roles"),
    Step(keys=("a",), wait_for="Add a role"),
    Step(
        keys=("demo-role", "enter"), wait_for="Grants", timeout=8.0, label="Role created"
    ),  # auto-opens RoleViewScreen
    Step(keys=("tab", "tab", "tab")),  # focus the (empty) grants table
    Step(keys=("a",), wait_for="Add grant"),
    Step(
        keys=("enter",), wait_for="Permissions", timeout=8.0, label="Adding an identity grant"
    ),  # grant type "identity" (default cursor); opens as a popup over RoleViewScreen
    Step(keys=("ctrl+s",), wait_for="identity", timeout=8.0),  # confirm defaults, back to RoleViewScreen
    Step(keys=("a",), wait_for="Add grant"),
    Step(
        keys=("down", "enter"), wait_for="Permissions", timeout=8.0, label="Adding a tag grant"
    ),  # grant type "tag" (index 1)
    Step(keys=("ctrl+s",), wait_for="tag", timeout=8.0),  # confirm defaults
    Step(keys=("ctrl+s",), timeout=8.0),  # save role
    Step(keys=("escape",), wait_for="Grants", timeout=8.0),  # back to RoleListScreen (column header)
    # Boundaries
    Step(keys=("shift+tab", "down", "enter"), wait_for="Ceiling", timeout=8.0, label="Boundaries"),
    Step(keys=("a",), wait_for="Add a boundary"),
    Step(
        keys=("demo-zone", "enter"), wait_for="demo-zone", timeout=8.0, label="Boundary created"
    ),  # auto-opens BoundaryViewScreen
    Step(keys=("escape",), wait_for="Ceiling", timeout=8.0),  # back to BoundaryListScreen
    # Authentication
    Step(keys=("shift+tab", "down", "enter"), wait_for="Enabled", timeout=8.0, label="Authentication"),
    Step(keys=("a",), wait_for="Auth type"),
    Step(keys=("enter",), wait_for="New http_sig auth"),  # default cursor on http_sig
    Step(
        keys=("demo-auth", "tab", "cli", "enter"), wait_for="Enabled", timeout=8.0, label="Auth created"
    ),  # auto-opens AuthViewScreen
    Step(keys=("escape",), wait_for="Client Type", timeout=8.0),  # back to AuthListScreen
    # Bastions
    Step(keys=("shift+tab", "down", "enter"), wait_for="SSH Proxy Jump", timeout=8.0, label="Bastions"),
    Step(keys=("a",), wait_for="Add a bastion"),
    Step(
        keys=("https://demo-bastion.example.com", "tab", "proxy.example.com", "enter"),
        wait_for="demo-bastion",
        timeout=8.0,
        label="Bastion created",
    ),  # auto-opens BastionViewScreen
    Step(keys=("escape",), wait_for="SSH Proxy Jump", timeout=8.0),  # back to BastionListScreen
    # Tenants
    Step(keys=("shift+tab", "down", "enter"), wait_for="Display Name", timeout=8.0, label="Tenants"),
    Step(keys=("a",), wait_for="Add a tenant"),
    Step(keys=("acme", "tab", "Acme Corp", "enter"), wait_for="acme", timeout=8.0, label="Tenant created"),
    # Audit log (last section, group "Audit")
    Step(keys=("shift+tab", "down", "enter"), wait_for="Time", timeout=8.0, label="Audit log"),
    Step(keys=("ctrl+q",)),  # quit
]
