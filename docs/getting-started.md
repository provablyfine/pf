# Getting started

## Install pf

### Native Windows

On Windows, you can instead download `pf-setup.exe` from the
[latest release](https://github.com/provablyfine/pf/releases/latest) and run
it. The installer is currently unsigned, so Windows SmartScreen will warn you on
first run; choose "More info" then "Run anyway" to proceed.

The installer installs pf for the current user. To install it for all users in
`C:\Program Files\pf`, choose that in the installer, or run it with `/ALLUSERS`.
You need that to use the machine as a host.

### Linux packages

For simple cli use, we recommend pipx:
```console
$ pipx install provablyfine
```

For hosts you want to connect to via `pf`, we publish `.deb` and `.rpm` packages on the
[latest release](https://github.com/provablyfine/pf/releases/latest) page.

We support the following releases:
| Distribution | Versions |
| --- | --- |
| Debian | 12, 13 |
| Ubuntu | 22.04, 24.04 |
| RHEL and rebuilds | 9, 10 |
| Fedora | 43, 44 |

### macOS

We recommend to use `pipx` to install pf. From a terminal, run this command:

```console
$ pipx install provablyfine
```

### Check that the install has worked

And then, check that it has been installed successfully:
```console
$ pf --version
{{pf_version}}
```

## Create your first tenant

The fastest way to create your first tenant is to use our
[demo environment](https://demo.provablyfine.net/). After you login for
the first time, choose an organization name. From the main page,
the list of tenants, click on **Add tenant**. Choose a tenant name, click
**Create**, and wait a couple of seconds until the list of tenants displays
the new tenant!

## Connect with your new tenant

From the list of tenants, click on the **Connect** button to display the
commands needed and run the `accept` command:
```console
$ pfa accept --invitation https://demo.provablyfine.net/pf/t/<tenant-uuid>/directory
```

You can now login
```console
$ pfa login
```

The login command triggers a browser-based login and saves your temporary (30
minutes) session key in your local `ssh-agent`. All other local CLI commands will
use this key transparently until it expires.

If you do not have a local `ssh-agent`, `login` will ask for confirmation
to store the session key as cleartext in your local configuration file
`~/.config/pf/config.json`.

## Check your connection

If you get pong, you are authenticated successfully:
```
$ pf ping
pong
```

## Register a new server

If you have an OpenSSH (>= 7.4, released in december 2016) service installed on your server,
you can register it within your tenant.

### Create a new host identity

First, on your local host, create an identity associated with this OpenSSH server instance:
```console
$ pfa identity create -n demo --tag id=device
$ INVITATION_URL=$(pfa identity invite --manual -i $(pfa identity list -n demo -q))
```

### Grant yourself access to the host

```
# Create a role
$ pfa role create -n users
$ USERS_ROLE_ID=$(pfa role list -n users -q)
# Grant ssh permissions to all hosts to the new role
$ pfa grant ssh --username root --capability shell pty user-rc --tag id=device | pfa role grant -i $USERS_ROLE_ID --set
# Add ourselves to the role
$ pfa role member -i $USERS_ROLE_ID -a $(pfa whoami)
```

### Setup the host

You need to install first `pf` on the server globally:
```console
$ pip install --global provablyfine
```

Then, make your OpenSSH service know about the new centralized
authentication system. Run this command on the server as root:
```console
$ sudo pf openssh host-init --invitation $INVITATION_URL
```

To see what the command would change without changing anything, add `--dry-run`.
To undo the changes, run `sudo pf openssh host-uninit`.

### Setup a macOS host

Install the macOS installer package from the
[latest release](https://github.com/provablyfine/pf/releases/latest) page.
A `pf` installed with `pipx` or Homebrew does not work on a host.
sshd only runs a command when only root can change it and every directory above it.

Then run this command in a terminal:
```console
$ sudo pf openssh host-init --invitation $INVITATION_URL
```

macOS starts sshd for each connection, so there is nothing to restart.
The command also installs three launchd jobs.
They refresh the host certificates, register the host with the bastion, and end sessions
when their certificate deadline passes.

If Remote Login is off, the command tries to turn it on.
Check it in System Settings, under General, Sharing.
macOS only lets the members of the group `com.apple.access_ssh` log in over SSH, when that group exists.
The command prints the `dseditgroup` command to add a user.

### Setup a Windows host

Install pf for all users. Run the installer, and choose to install for all users
when it asks, or run it with `/ALLUSERS`.
This puts pf in `C:\Program Files\pf`.
A pf installed for one user does not work on a host.
sshd only runs a command when only administrators can change it and every folder above it.

The host also needs the OpenSSH Server feature of Windows.

Then run this command in a terminal opened with Run as administrator:
```console
> pf openssh host-init --invitation $INVITATION_URL
```

The command adds one `Include` line at the top of `C:\ProgramData\ssh\sshd_config`.
It keeps a copy of the file, checks the new one with `sshd -t`, and restarts the sshd service.
Sessions that are open stay open.
If sshd rejects the new file or does not restart, the command puts the old file back.

The command creates a local user named `pf-auth` with no rights.
sshd runs its check of the certificate as this user.
It also adds three tasks to the Task Scheduler, in the folder `provablyfine`.
They refresh the host certificates, register the host with the bastion, and end sessions
when their certificate deadline passes.

To remove all of this, run `pf openssh host-uninit` in the same way.
Windows keeps the folder of the deleted user in `C:\Users`.

## Connect to your new host

First, you need to login under the `users` role:
```console
$ pf login -r users
Open https://demo.provablyfine.net/device?user_code=TJCK-RJUX
Enter code: TJCK-RJUX
```

And then, replace the usual `ssh` command with `pf ssh`: it is compatible
with the OpenSSH `ssh` binary CLI.
```console
$ pf ssh root@demo echo hello
hello
```

## Onboard new users via email

### Login as admin

```
$ pfa login
Open https://demo.provablyfine.net/device?user_code=TJCK-RCUX
Enter code: TJCK-RCUX
  1. admin
  2. users
Select role [1-2]: 1
```

### Create a new user identity

```console
$ pfa identity create -n julie.chloe@gmail.com
```

### Grant permissions to the new user

We are going to make this new user a member of the `users` role
for convenience:
```console
$ pfa role -i $(pfa role list -n users -q) -a julie.chloe@gmail.com
```

### Invite the user

Create an invitation, and send it to this user via email:
```console
$ pfa identity invite --email -i $(pfa identity list -n julie.chloe@gmail.com -q)
```

### Accept the invitation

After you share the invitation with your new user, she receives an email
that describes how to connect via the SSO:
```console
$ pf accept https://demo.provablyfine.net/pf/t/<tenant-uuid>/directory
```

. `accept` asks the user to
select which SSO to use, and completes login via a browser popin
before coming back to the terminal:

She can then look at which hosts she is allowed to access:
```console
$ pf login
Open https://demo.provablyfine.net/device?user_code=TJCK-ICUX
Enter code: TJCK-ICUX
  1. admin
  2. users
Select role [1-2]: 1
$ pf hosts
host             type    username    details
---------------  ------  ----------  ---------
laptop-ml-perso  shell   root
laptop-ml-perso  shell   mathieu
```

## Prefer a terminal UI?

Every `pfa` command above (and more) is also available from `pfat`, a
terminal UI for administrators:

```console
$ pfat
```

<div id="tour-quick"></div>
<script>
  document.addEventListener("DOMContentLoaded", () => {
    AsciinemaPlayer.create(
      "../assets/tui-tour-quick.cast",
      document.getElementById("tour-quick"),
      {cols: 100, rows: 30, idleTimeLimit: 4.5, loop: true, preload: true, autoplay: true, keystrokeOverlay: true, controls: true}
    );
  });
</script>

See the [Admin TUI](admin/tui.md) page for a full walkthrough of every screen.

## Next steps

The setup we have completed is pretty basic. A more realistic setup would
require a clear mapping of your security policy (who can access which hosts)
to a set of [identities](XXX), [tags](XXX), [roles](XXX), and [boundaries](XXX).

Realistically, most administrators probably want to authenticate users via
their own [OIDC SSO](admin/oidc.md).

You also need to prepare a strategy to automate [host enrollment](XXX) in your
tenant, ideally so that it happens when hosts are provisionned.
