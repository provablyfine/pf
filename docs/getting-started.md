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

## Create your private key

Create a new *account* key. Keep track of your passphase and the key fingerprint:
```console
$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/mathieu/.ssh/id_ed25519): /home/mathieu/.ssh/pf-root   
Enter passphrase for "/home/mathieu/.ssh/pf-root" (empty for no passphrase): 
Enter same passphrase again: 
[...]
The key fingerprint is:
SHA256:lSW6nwnEz+dxa2WMI8+xBdCccNAOSmJikRABI3xPYuY mathieu@Host-001
[...]
```

## Initialize your tenant

Now, you need to establish your *account* private key as the sole identity 
trusted to bootstrap your tenant's configuration, until you configure other 
authentication methods later. 

```console
$ pfa initialize  https://api.provablyfine.net/pf/t/root --key SHA256:lSW6nwnEz+dxa2WMI8+xBdCccNAOSmJikRABI3xPYuY
XXX
```

Initialization is strictly a one-time operation: if you lose access to your
*account* key, you will need to create a new tenant from scratch.

After the tenant is initialized, this command also saves in `~/.config/pf/config.json` your
tenant url and your *account* key fingerprint.

## Register a new host

If you have a recent-enough (XXX) OpenSSH server installed on your host, you can register
it within your tenant. 

### Create a new identity

First, create an identity associated with this OpenSSH server instance:
```console
$ pfa identity create -n my-new-hostname
$ IDENTITY_ID=$(pfa identity list -n my-new-hostname -q)
$ pfa identity invite --manual -i $IDENTITY_ID
XXX
```

### Download all-in-one image

Download the image for your pf release:
```console
$ curl $(pf host print-download-url)
XXX
```

### Install all-in-one image

Start the image with your invitation key:
```console
$ sudo pf host setup --raw-image=./pf-all-in-one.raw --invitation-key=INVITATION_KEY
```

Alternatively, if you feel uncomfortable running a pf command as root via sudo, you
can also ask pf to generate a shell script and audit it before running it:
```console
$ pf host setup --print-bash
```

You can check that our new OpenSSH service is running:
```console
$ systemctl status pf-host
```

## Connect to your new host

The `pf ssh` command is compatible with the OpenSSH `ssh` binary:
```console
$ pf ssh root@my-new-hostname echo hello
hello
```


## Next steps

The setup we have completed is pretty basic. A more realistic setup would
require a clear mapping of your security policy (who can access which hosts)
to a set of [identities](XXX), [tags](XXX), [roles](XXX), and [boundaries](XXX).

Realistically, most administrators also would setup an external [OIDC SSO](XXX) to 
authenticate users.
