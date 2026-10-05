# OIDC Authentication

By default, if you self-host provablyfine the system is configured
to require users to log in via personal SSH keys. The managed
demo environment we provide for free to help explore provablyfine is
pre-configured to trust Google, GitHub, GitLab, and Codeberg so that
if you have an active account within one of these systems, you
can log in trivially.

In both self-hosted and managed environments, you can extend the
default configuration to allow your users to log in with your
existing OIDC identity provider (Okta, Microsoft Entra, Google
Workspace, Keycloak, and so on).

## Supported Identity Providers

Provablyfine acts as a standard OIDC client that uses the OIDC
device code flow.

The following IdPs have been tested and are known to work:

- Google
- Keycloack
- Codeberg
- GitLab

The following IdPs are not supported:

- GitHub

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
   already exist, and its name must be that email address.
5. A session is created. It expires after `session_duration_s` (1 hour by default).

## Choosing an auth type

There are three OIDC auth types:

| Type | Client type | Flow | Needs a client secret |
| --- | --- | --- | --- |
| `oidc` | web | Browser redirect | No |
| `oidc-device-code` | cli | Device code | No |
| `oidc-secret-device-code` | cli | Device code | Yes |

The device code flow prints a URL and a short code. The user opens the URL on any
device (typically their laptop or phone), signs in, and enters the code. Our CLI
and TUI poll the provider until the user is done. This works well for terminals,
including remote SSH sessions. Use `oidc-device-code` by default.
`oidc-secret-device-code` is needed for some IdPs that have creative interpretations
of the OIDC specification, aka, Google.

The `oidc` type is for web applications that run their own browser redirect flow.
It is currently used exclusively by our managed demo environment. You do not need
to use it, unless you have built a pure browser-based client for the provablyfine
API.


## Setting up your provider

### Google

Create an application from the [Google Cloud Console](https://console.cloud.google.com):

1. Create a Project if you don't have one already and then select it.
2. Go to "Google Auth Platform" from within the search bar
3. In the "Branding" section, fill branding information
4. In the "Client" section, create a client of type "Desktop". Save `Client ID`  and `Client secret`
5. In the "Data access" section, configure the "userinfo.email" scope

and then create an `auth` within provablyfine:

```console
pfa auth create oidc-secret-device-code -n google \
    --issuer https://accounts.google.com \
    --client-id CLIENT_ID --client-secret CLIENT_SECRET
```

### GitLab

Create an application from the GitLab user settings:

1. Go to the [Applications](https://gitlab.com/-/user_settings/applications) page
2. Click on "Add new application"
3. Fill the fields:
   - name: whatever you want
   - redirect url: "http://127.0.0.1/callback"
   - uncheck "Confidential"
   - check "Device authorization grant"
   - check "openid" and "email" scopes
4. Click "Save application", save the client id displayed on screen

and then create an `auth` within provablyfine:

```console
pfa auth create oidc -n gitlab --issuer https://gitlab.com \
    --client-id CLIENT_ID
```

### Codeberg

Create an application from the Codeberg settings:

1. Go to the [Applications](https://codeberg.org/user/settings/applications) page
2. Fill the fields:
   - application name: whatever you want
   - redirect URIs: http://127.0.0.1/callback
   - uncheck "Confidential client"
3. At the bottom of the page, click on "Create application"

and then create an `auth` within provablyfine:

```console
pfa auth create oidc -n codeberg --issuer https://codeberg.org \
    --client-id CLIENT_ID
```
