# Admin TUI

`pfat` is a terminal UI for administrators. It covers the same ground as the
`pfa` CLI — tenants, identities, bastions, boundaries, tags, roles and their
grants, authentication methods, and the audit log — without needing to
remember individual subcommands.

```console
$ pfat
```

The recording below is a full walkthrough: logging in, then creating a
tenant, an identity (and inviting it), a bastion, a boundary, a tag, a role
with two grants, and an authentication method, finishing on the audit log
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
| `escape`            | back (or quit, from the Home screen)      |
| `a`                 | add                                       |
| `d`                 | delete                                    |
| `ctrl+s`            | save                                      |

From the Home screen, each resource (Tenants, Identities, Bastions,
Boundaries, Tags, Roles, Auths, Audit Log) opens into its own list, and each
list opens into a detail view for the selected row.
