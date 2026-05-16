# Getting started

## Install pf

We recommend to use `pip` to install pf. From a terminal, run this command:

```console
$ pip install --user provablyfine
XXX
```

And then, check that it has been installed successfully:
```console
$ pf --version
XXX
```

## Create your first tenant

The fastest way to create your first tenant is to use the free tier of our
[managed instance](https://pf.provablyfine.net/). After you login,
choose a tenant name that is available, and wait for the email that contains
the initialization url for your tenant.

!!! note
    If you are using your own internal pf deployment, ask your pf administrator
    to create the tenant for you, and share with you the associated initialization url.


## Create your private key

By default, a new tenant is configured to authenticate users via private/public keys:
each identity is associated with one or more *account* private/public key pairs. After
the tenant is initialized, you will be able to configure pf to perform authentication
via one of the builtin third-party SSOs or via your own OIDC-compatible SSO.

For now, although, you could reuse any existing key pair that you already have, we recommend
you create a new key pair that will become the key trusted by pf with root-level 
administrative access to your tenant:

```console
$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/mathieu/.ssh/id_ed25519): /home/mathieu/.ssh/pf-root   
Enter passphrase for "/home/mathieu/.ssh/pf-root" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/mathieu/.ssh/pf-root
Your public key has been saved in /home/mathieu/.ssh/pf-root.pub
The key fingerprint is:
SHA256:lSW6nwnEz+dxa2WMI8+xBdCccNAOSmJikRABI3xPYuY mathieu@Host-001
The key's randomart image is:
+--[ED25519 256]--+
|o o.++.o  . =*.. |
| o * .+.o..+.o=  |
|  = +. o+oo. o.  |
|   E . . =.   .+ |
|        S o + = =|
|         o = * O |
|          + . *  |
|             .   |
|                 |
+----[SHA256]-----+
```

Later, if you wish to, you will be able to disable human authentication via such priavte/public
key pairs to ensure all authentication happens via your external SSO.

Until you do this, because this key is a long-lived key associated with your pf administrative 
root account, we recommend you apply the usual security recommendations with SSH keys:

- do not use an empty passphrase
- pick a strong passphrase

## Initialize your tenant

Given your tenant url, `pfa`, the *administration* pf cli can initialize your tenant:

```console
$ pfa initialize  https://api.provablyfine.net/pf/t/root --key SHA256:lSW6nwnEz+dxa2WMI8+xBdCccNAOSmJikRABI3xPYuY
XXX
```

This command initializes the tenant database, creates the `root` identity, grants full permissions
to this identity, and associates this identity with the account key which matches the fingerprint
provided to the `--key` argument. This command also saves in `~/.config/pf/config.json` your
tenant url and your *account* key fingerprint.

## Register a new host

## Connect to your new host


