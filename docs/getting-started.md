# Getting started

## Install pf

We recommend to use `pip` to install pf. From a terminal, run this command:

```console
$ pip install --user provablyfine
XXX
```

And then, check that it has been installed successfully:
```console
$ pf version
0.2.0
```

## Create your first tenant

The fastest way to create your first tenant is to use the free tier of our
[managed instance](https://pf.provablyfine.net/). After you login,
choose a tenant name that is available, and wait for the email that contains
the initialization url for your tenant.

!!! note
    If you are using your own internal pf deployment, ask your pf administrator
    to create the tenant and share with you the associated initialization url.

## Initialize your tenant


If you have an `ssh-agent` already running, you just need:
```console
$ pfa initialize https://api.provablyfine.net/pf/t/your-tenant
XXX
```

This one-time operation creates an account key, asks for a passphrase to
encrypt it at rest in SSH format in your `~/.ssh/` directory, and associates this
key with your tenant's root identity.

After the tenant is initialized, this command also saves in `~/.config/pf/config.json` your
tenant url and your *account* key fingerprint.

## Register a new host

If you have a recent-enough (XXX) OpenSSH server installed on your host, you can register
it within your tenant.

### Create a new host identity

First, create an identity associated with this OpenSSH server instance:
```console
$ pfa login
$ pfa identity create -n demo
$ pfa identity invite --manual -i $(pfa identity list -n demo -q)
https://api.provablyfine.net/pf/t/your-tenant/directory?invitation=R1_fe_2G60SE9neYHFJojuwHMKKDsdPEMiO_Hzw&auth=default
```

### Setup the host

Then, make your local OpenSSH daemon know about the new centralized
authentication system:
```console
$ pf -c demo.json openssh host-init https://api.provablyfine.net/pf/t/your-tenant/directory?invitation=R1_fe_2G60SE9neYHFJojuwHMKKDsdPEMiO_Hzw&auth=default | sudo bash -s
```

## Connect to your new host

The `pf ssh` command is compatible with the OpenSSH `ssh` binary:
```console
$ pf ssh root@demo echo hello
hello
```

## Onboard new users via email

While you can onboard new users via private/public key authentication, like you
you authenticated the `root` user during tenant initialization,
it is often more convenient to authenticate via one of our builtin SSOs (google,
gitlab, XXX).

### Create a new user identity

```console
$ pfa identity create -n julie.chloe@gmail.com
```

### Grant permissions to the new user

We are going to make this new user a member of the builtin `root` role
for convenience:
```console
$ pfa role -i $(pfa role list -n root -q) -a julie.chloe@gmail.com
```

### Invite the user

Create an invitation, and send it to this user via email:
```console
$ pfa identity invite --email -i $(pfa identity list -n julie.chloe@gmail.com -q)
```

### Accept the invitation

After you share the invitation with your new user, she receives an email
that describes how to connect via the SSO. `accept` asks the user to
select which SSO to use, and completes login via a browser popin
before coming back to the terminal:
```console
$ pf accept https://api.provablyfine.net/pf/t/your-tenant/directory
XXX
```

She can then look at which hosts she is allowed to access:
```console
$ pf hosts
XXX
```

## Next steps

The setup we have completed is pretty basic. A more realistic setup would
require a clear mapping of your security policy (who can access which hosts)
to a set of [identities](XXX), [tags](XXX), [roles](XXX), and [boundaries](XXX).

Realistically, most administrators probably want to authenticate users via
their own [OIDC SSO](XXX).

You also need to prepare a strategy to automate [host enrollment](XXX) in your
tenant, ideally so that it happens when hosts are provisionned.
