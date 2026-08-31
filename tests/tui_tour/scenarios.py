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


# Home → Identities list → identity detail → back → Audit Log list → quit.
# Browse-only: no typing, no creation. Needs pre-seeded named identities and
# at least one audit log entry (the seeding calls themselves produce some).
QUICK_TOUR: list[Step] = [
    Step(wait_for="Resources", label="Home screen"),
    Step(keys=("down",)),  # highlight Identities
    Step(keys=("enter",), wait_for="Unix username", label="Identities list"),  # IdentityListScreen
    Step(keys=("enter",), wait_for="Unix username", label="Identity detail"),  # IdentityViewScreen for row 0
    Step(keys=("escape",), wait_for="Unix username"),  # back to IdentityListScreen
    Step(keys=("escape",), wait_for="Resources"),  # back to Home
    Step(keys=("down", "down", "down", "down", "down", "down")),  # Identities(1) -> Audit Log(7)
    Step(keys=("enter",), wait_for="Time", label="Audit log"),  # AuditLogListScreen (column header)
    Step(keys=("escape",), wait_for="Resources"),  # back to Home
    Step(keys=("escape",)),  # app.quit
]


# Real login, then every resource section in Home's list order, each one
# creating its own demo data live. Section order matches home._RESOURCES so
# each section's Home navigation is a single relative "down" from wherever
# the cursor was left by the previous section.
THOROUGH_TOUR: list[Step] = [
    # Login (ReloginScreen -> auto http_sig login -> TuiApp Home)
    Step(wait_for="Reconnecting", timeout=10.0, label="Logging in"),
    Step(wait_for="Resources", timeout=15.0, label="Home screen"),
    # Tenants (index 0)
    Step(keys=("enter",), wait_for="Display Name", timeout=8.0, label="Tenants"),
    Step(keys=("a",), wait_for="Add a tenant"),
    Step(keys=("acme", "tab", "Acme Corp", "enter"), wait_for="acme", timeout=8.0, label="Tenant created"),
    Step(keys=("escape",), wait_for="Resources"),
    # Identities (index 1): create, then invite (seeded throwaway secret)
    Step(keys=("down", "enter"), wait_for="Unix username", timeout=8.0, label="Identities"),
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
    Step(keys=("escape",), wait_for="Resources"),
    # Bastions (index 2)
    Step(keys=("down", "enter"), wait_for="SSH Proxy Jump", timeout=8.0, label="Bastions"),
    Step(keys=("a",), wait_for="Add a bastion"),
    Step(
        keys=("https://demo-bastion.example.com", "tab", "proxy.example.com", "enter"),
        wait_for="demo-bastion",
        timeout=8.0,
        label="Bastion created",
    ),  # auto-opens BastionViewScreen
    Step(keys=("escape",), wait_for="SSH Proxy Jump", timeout=8.0),  # back to BastionListScreen
    Step(keys=("escape",), wait_for="Resources"),
    # Boundaries (index 3)
    Step(keys=("down", "enter"), wait_for="Ceiling", timeout=8.0, label="Boundaries"),
    Step(keys=("a",), wait_for="Add a boundary"),
    Step(
        keys=("demo-zone", "enter"), wait_for="demo-zone", timeout=8.0, label="Boundary created"
    ),  # auto-opens BoundaryViewScreen
    Step(keys=("escape",), wait_for="Ceiling", timeout=8.0),  # back to BoundaryListScreen
    Step(keys=("escape",), wait_for="Resources"),
    # Tags (index 4)
    Step(keys=("down", "enter"), wait_for="Value", timeout=8.0, label="Tags"),
    Step(keys=("a",), wait_for="Add a tag"),
    Step(keys=("env", "tab", "demo", "enter"), wait_for="env", timeout=8.0, label="Tag created"),
    Step(keys=("escape",), wait_for="Resources"),
    # Roles (index 5): create, add two grant types to the grant editor
    Step(keys=("down", "enter"), wait_for="Members", timeout=8.0, label="Roles"),
    Step(keys=("a",), wait_for="Add a role"),
    Step(
        keys=("demo-role", "enter"), wait_for="Grants", timeout=8.0, label="Role created"
    ),  # auto-opens RoleViewScreen
    Step(keys=("tab", "tab", "tab")),  # focus the (empty) grants table
    Step(keys=("a",), wait_for="Add grant"),
    Step(
        keys=("enter",), wait_for="Permissions", timeout=8.0, label="Adding an identity grant"
    ),  # grant type "identity" (default cursor)
    Step(keys=("ctrl+s",), wait_for="identity", timeout=8.0),  # confirm defaults, back to RoleViewScreen
    Step(keys=("a",), wait_for="Add grant"),
    Step(
        keys=("down", "enter"), wait_for="Permissions", timeout=8.0, label="Adding a tag grant"
    ),  # grant type "tag" (index 1)
    Step(keys=("ctrl+s",), wait_for="tag", timeout=8.0),  # confirm defaults
    Step(keys=("ctrl+s",), timeout=8.0),  # save role
    Step(keys=("escape",), wait_for="Grants", timeout=8.0),  # back to RoleListScreen (column header)
    Step(keys=("escape",), wait_for="Resources"),
    # Auths (index 6)
    Step(keys=("down", "enter"), wait_for="Enabled", timeout=8.0, label="Auths"),  # AuthListScreen ("Enabled" column)
    Step(keys=("a",), wait_for="Auth type"),
    Step(keys=("enter",), wait_for="New http_sig auth"),  # default cursor on http_sig
    Step(
        keys=("demo-auth", "tab", "cli", "enter"), wait_for="Enabled", timeout=8.0, label="Auth created"
    ),  # auto-opens AuthViewScreen
    Step(keys=("escape",), wait_for="Client Type", timeout=8.0),  # back to AuthListScreen
    Step(keys=("escape",), wait_for="Resources"),
    # Audit Log (index 7)
    Step(keys=("down", "enter"), wait_for="Time", timeout=8.0, label="Audit log"),
    Step(keys=("escape",), wait_for="Resources"),
    Step(keys=("escape",)),  # app.quit
]
