# OIDC Authentication

You can let your users log in to provablyfine with your existing identity provider
(Okta, Microsoft Entra, Google Workspace, Keycloak, and so on) instead of managing
SSH keys or invitations for every person. You register your provider once as an
*auth* in your tenant, and each login proves the user's identity to that provider.

provablyfine acts as a standard OIDC client here. Nothing is configured in the
server's YAML file. The provider's details live in the auth record you create.

## How it works

1. The user runs `pf login`. The CLI starts the flow your auth type defines, and the
   user signs in at your identity provider.
2. The CLI receives an `id_token` from the provider. It generates a short-lived
   session key, and sends the token to the API server, signed with that key. This
   proof-of-possession means a stolen token alone is not enough to log in.
3. The server verifies the token against your provider: it fetches the provider's
   discovery document and key set, checks the signature, and checks the issuer,
   audience, expiry and nonce claims.
4. The server matches the token's `email` claim to an identity. The identity must
   already exist, and its name must be that email address. See
   [Creating the auth](#creating-the-auth) below.
5. A session is created. It expires after `session_duration_s` (1 hour by default),
   and the user logs in again. The `pfat` TUI detects the expiry and re-runs the
   login flow for you.

Each `id_token` can be used exactly once. Replays are rejected.

## Choosing an auth type

There are three OIDC auth types. Pick by what your users log in with, and by whether
your provider issued a public or a confidential client.

| Type | Client type | Flow | Needs a client secret |
| --- | --- | --- | --- |
| `oidc` | web | Browser redirect | No |
| `oidc-device-code` | cli | Device code | No |
| `oidc-secret-device-code` | cli | Device code | Yes |

The device code flow prints a URL and a short code. The user opens the URL on any
device (typically their laptop or phone), signs in, and enters the code. The CLI
polls the provider until the user is done. It works well for terminals, including
remote SSH sessions, because the terminal itself never needs to host a redirect.

`pf` and `pfat` use the CLI types. The `oidc` type is for web applications that run
their own browser redirect flow.

## Setting up your provider

Create an OIDC application (or "app registration") in your provider:

- Choose a native/public application for `oidc-device-code`, or a confidential
  (server-side) one for `oidc-secret-device-code`.
- Enable the device authorization grant. The provider must publish a
  `device_authorization_endpoint` in its discovery document.
- The application must issue tokens containing the `email` claim. The requested
  scope is `openid email`, so make sure email is in the token.

You need two values from it: the issuer URL and the client ID. For a confidential
client you also need the client secret.

## Creating the auth

The identity must exist before the user's first login, and its name must be the
email address the provider will put in the token:

```console
$ pfa identity create -n alice@example.com
```

Then create the auth. With `pfat`, go to the Authentication section, press `a`,
pick the type, and fill in the name, issuer and client ID.

With `pfa`:

```console
$ pfa auth create oidc-device-code -n default --client-type cli \
    --issuer https://example.okta.com/oauth2/default \
    --client-id 0oabc123DEFghiJKLmno
```

A confidential client uses `oidc-secret-device-code` and adds
`--client-secret`. The secret is encrypted at rest with the tenant's key encryption
key.

An auth named `default` is picked up automatically by `pf login`. Otherwise pass
`--auth NAME`.

Two things to know:

- The issuer and client ID cannot be changed after creation. Delete and recreate
  the auth if they are wrong. The name, description, enabled flag and the email
  verification requirement are editable.
- By default the token's `email_verified` claim must be true. If your provider
  never sends that claim at all, pass `--allow-unverified-email`. This only
  tolerates a missing claim. A token that explicitly says the email is unverified
  is always rejected.

## Logging in

Users run:

```console
$ pf login
Open https://example.okta.com/activate
Enter code: WQJV-RFHG
```

They finish the sign-in in the browser, and the command completes on its own. If the
identity has several roles, `pf login` asks which one to activate.

## provablyfine as an OIDC provider

Separate note: provablyfine itself is also an OIDC issuer. Each tenant publishes
keys and issues short-lived JWTs that the bastion and register component use to
authenticate machine-to-machine connections. This is internal plumbing. There is
nothing for you to configure, and it is unrelated to the login setup on this page.
