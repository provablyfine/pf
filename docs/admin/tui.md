# Admin TUI

`pfat` is a terminal UI for administrators. It covers the same ground as the
`pfa` CLI — tenants, identities, bastions, boundaries, tags, roles and their
grants, authentication methods, and the audit log — without needing to
remember individual subcommands.

```console
$ pfat
```

The recording below is a full walkthrough: logging in, then creating an
identity (and inviting it), a tag, a role with two grants, a boundary, an
authentication method, a bastion, and a tenant, finishing on the audit log
that records everything that just happened.

<div id="tour-thorough"></div>
<script>
  document.addEventListener("DOMContentLoaded", () => {
    AsciinemaPlayer.create(
      "../../assets/tui-tour-thorough.cast",
      document.getElementById("tour-thorough"),
      {cols: 100, rows: 30, idleTimeLimit: 2, loop: true, preload: true, autoplay: true, keystrokeOverlay: true, controls: true}
    );
  });
</script>

## Navigation

The TUI is keyboard-driven throughout:

| Key                | Action                                    |
| ------------------- | ------------------------------------------ |
| `↑` / `↓`           | move the selection                        |
| `enter`             | open / select                             |
| `escape`            | back a level, or refocus the nav pane from a top-level list |
| `tab` / `shift+tab` | cycle focus, including into the nav pane  |
| `a`                 | add                                       |
| `d`                 | delete                                    |
| `ctrl+s`            | save                                      |
| `ctrl+q`            | quit                                      |

A navigation pane stays visible in the top-left corner of every screen,
grouping the same resources (Identities, Tags, Roles, Boundaries under
Access Control; Authentication, Bastions, Tenants under Admin; the Audit Log
under Audit) into a list you can jump to from anywhere with `shift+tab` then
`↑`/`↓`/`enter` — no need to back out of whatever you're doing first. Each
resource's list then opens into a detail view for the selected row.
