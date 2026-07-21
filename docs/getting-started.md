# Getting started

## Install pf

We recommend to use `pipx` to install pf. From a terminal, run this command:

```console
$ pipx install provablyfine
```

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
$ pfa accept --invitation https://demo.provablyfine.net/pf/t/your-tenant/directory
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
$ pfa grant ssh-shell --username root --tag id=device | pfa role grant -i $USERS_ROLE_ID --set
# Add ourselves to the role
$ pfa role member -i $USERS_ROLE_ID -a $(pfa whoami)
```

### Setup the host

You need to install first `pf` on the server globally:
```console
$ pip install --global provablyfine
```

Then, make your OpenSSH service know about the new centralized
authentication system. Run this command on the server:
```console
$ pf openssh host-init --invitation $INVITATION_URL | sudo bash -s
```

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
$ pf accept https://demo.provablyfine.net/pf/t/your-tenant/directory
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

## Next steps

The setup we have completed is pretty basic. A more realistic setup would
require a clear mapping of your security policy (who can access which hosts)
to a set of [identities](XXX), [tags](XXX), [roles](XXX), and [boundaries](XXX).

Realistically, most administrators probably want to authenticate users via
their own [OIDC SSO](XXX).

You also need to prepare a strategy to automate [host enrollment](XXX) in your
tenant, ideally so that it happens when hosts are provisionned.
