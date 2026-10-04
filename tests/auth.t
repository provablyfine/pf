Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List auth configs (default http_sig config was created at init)
  $ pfa -c config.json auth list
    id  name     client_type    type      enabled    description
  ----  -------  -------------  --------  ---------  -------------------------------------
     1  default  cli            http_sig  True       Default HTTP signature authentication

List auth configs (quiet)
  $ pfa -c config.json auth list -q
  1

Read the default auth config
  $ pfa -c config.json auth read -i 1
  id           1
  name         default
  client_type  cli
  type         http_sig
  description  Default HTTP signature authentication
  enabled      True
  created_at   .* (re)

Create a new http_sig auth config
  $ pfa -c config.json auth create http_sig -n corporate --client-type cli

List auth configs (two now)
  $ pfa -c config.json auth list -q
  1
  2

Read the new auth config
  $ pfa -c config.json auth read -i 2
  id           2
  name         corporate
  client_type  cli
  type         http_sig
  description
  enabled      True
  created_at   .* (re)

Create a duplicate auth config (same name + client_type)
  $ pfa -c config.json auth create http_sig -n default --client-type cli
  Auth config already exists
  [2]

Create same name with different client_type (allowed)
  $ pfa -c config.json auth create http_sig -n default --client-type web

List auth configs (three now)
  $ pfa -c config.json auth list -q
  1
  2
  3

Delete the web variant
  $ pfa -c config.json auth delete -i 3

Create an auth config with an integer name (should fail)
  $ pfa -c config.json auth create http_sig -n 42 --client-type cli
  Auth config name must not be a pure integer
  [2]

Create an oidc auth config for a cli client (should fail)
  $ pfa -c config.json auth create oidc -n bad --client-type cli --issuer https://accounts.google.com --client-id my-client-id 2>&1 | grep -o "invalid choice"
  invalid choice

Create an oidc auth config
  $ pfa -c config.json auth create oidc -n google --client-type web --issuer https://accounts.google.com --client-id my-client-id

Read the oidc auth config
  $ pfa -c config.json auth read -i 4
  id                      4
  name                    google
  client_type             web
  type                    oidc
  description
  enabled                 True
  created_at    .* (re)
  issuer                  https://accounts.google.com
  client_id               my-client-id
  callback_url            http://127.0.0.1/callback
  require_email_verified  True

Create an oidc auth config without issuer (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --client-type web --client-id my-client-id 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --issuer

Create an oidc auth config without client-id (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --client-type web --issuer https://accounts.google.com 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --client-id

Create an oidc auth config that allows unverified email
  $ pfa -c config.json auth create oidc -n unverified-ok --client-type web --issuer https://accounts.google.com --client-id my-client-id-2 --allow-unverified-email
  $ pfa -c config.json auth read -i 5 -f json | jq .config.require_email_verified
  false

Update it to require verified email again
  $ pfa -c config.json auth update -i 5 --require-verified-email
  $ pfa -c config.json auth read -i 5 -f json | jq .config.require_email_verified
  true

Update auth config name
  $ pfa -c config.json auth update -i 2 --name corp-http-sig
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  client_type  cli
  type         http_sig
  description
  enabled      True
  created_at   .* (re)

Update auth config description
  $ pfa -c config.json auth update -i 2 --description "Corporate HTTP signature auth"
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  client_type  cli
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)

Disable an auth config
  $ pfa -c config.json auth update -i 2 --disable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  client_type  cli
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      False
  created_at   .* (re)

Re-enable an auth config
  $ pfa -c config.json auth update -i 2 --enable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  client_type  cli
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)

Public discovery endpoint returns correct data for http_sig
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth/default?client_type=cli" && echo ""
  {"name":"default","description":"Default HTTP signature authentication","config":{"type":"http_sig"}}

Public discovery endpoint returns correct data for oidc
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth/google?client_type=web" && echo ""
  {"name":"google","description":"","config":{"issuer":"https://accounts.google.com","client_id":"my-client-id","client_secret":null,"callback_url":"http://127.0.0.1/callback","require_email_verified":true,"type":"oidc"}}

Public list endpoint filters by client_type
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth?client_type=cli" | jq -r '.auths[].name'
  default
  corp-http-sig

Public list endpoint includes web oidc configs under client_type=web
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth?client_type=web" | jq -r '.auths[].name'
  google
  unverified-ok

Public discovery endpoint returns 404 for unknown name
  $ curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth/nonexistent?client_type=cli"
  404

Public discovery endpoint returns 404 for disabled auth config
  $ pfa -c config.json auth update -i 4 --disable
  $ curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth/google?client_type=web"
  404
  $ pfa -c config.json auth update -i 4 --enable

Read a non-existent auth config
  $ pfa -c config.json auth read -i 999
  Auth config not found
  [2]

Update a non-existent auth config
  $ pfa -c config.json auth update -i 999 --name whatever
  Auth config not found
  [2]

Delete an auth config
  $ pfa -c config.json auth delete -i 2
  $ pfa -c config.json auth list -q
  1
  4
  5

Delete a non-existent auth config
  $ pfa -c config.json auth delete -i 999
  Auth config not found
  [2]

pf login uses the default auth config by default
  $ ssh-keygen -t ed25519 -f session2 -N "" > /dev/null
  $ pf -c config.json login --session-key session2

pf login uses the specified auth config by name
  $ ssh-keygen -t ed25519 -f session3 -N "" > /dev/null
  $ pf -c config.json login --session-key session3 --auth default

pf login fails if the auth config does not exist
  $ ssh-keygen -t ed25519 -f session4 -N "" > /dev/null
  $ pf -c config.json login --session-key session4 --auth nonexistent
  Auth config 'nonexistent' not found
  [2]

Create an oidc-device-code auth config for a web client (should fail)
  $ pfa -c config.json auth create oidc-device-code -n bad --client-type web --issuer https://accounts.google.com --client-id device-client-id 2>&1 | grep -o "invalid choice"
  invalid choice

Create an oidc-device-code auth config
  $ pfa -c config.json auth create oidc-device-code -n device --client-type cli --issuer https://accounts.google.com --client-id device-client-id

Read the oidc-device-code auth config
  $ pfa -c config.json auth read -i 6
  id                      6
  name                    device
  client_type             cli
  type                    oidc-device-code
  description
  enabled                 True
  created_at    .* (re)
  issuer                  https://accounts.google.com
  client_id               device-client-id
  require_email_verified  True

oidc-device-code has no client secret to give it
  $ pfa -c config.json auth create oidc-device-code -n device-secret --client-type cli --issuer https://accounts.google.com --client-id x --client-secret s 2>&1 | grep "error:"
  pfa: error: unrecognized arguments: --client-secret s

Create an oidc-secret-device-code auth config without a secret (should fail)
  $ pfa -c config.json auth create oidc-secret-device-code -n bad --client-type cli --issuer https://accounts.google.com --client-id x 2>&1 | grep "error:"
  pfa auth create oidc-secret-device-code: error: the following arguments are required: --client-secret

Create an oidc-secret-device-code auth config for a web client (should fail)
  $ pfa -c config.json auth create oidc-secret-device-code -n bad --client-type web --issuer https://accounts.google.com --client-id x --client-secret s 2>&1 | grep -o "invalid choice"
  invalid choice

Create an oidc-secret-device-code auth config
  $ pfa -c config.json auth create oidc-secret-device-code -n device-secret --client-type cli --issuer https://accounts.google.com --client-id secret-client-id --client-secret my-secret

Read the oidc-secret-device-code auth config
  $ pfa -c config.json auth read -i 7
  id                      7
  name                    device-secret
  client_type             cli
  type                    oidc-secret-device-code
  description
  enabled                 True
  created_at    .* (re)
  issuer                  https://accounts.google.com
  client_id               secret-client-id
  require_email_verified  True
  client_secret           my-secret

The secret is sent to the cli that runs the flow
  $ curl -s "http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/public/auth/device-secret?client_type=cli" && echo ""
  {"name":"device-secret","description":"","config":{"issuer":"https://accounts.google.com","client_id":"secret-client-id","client_secret":"my-secret","require_email_verified":true,"type":"oidc-secret-device-code"}}

require_email_verified applies to both device code types
  $ pfa -c config.json auth update -i 6 --allow-unverified-email
  $ pfa -c config.json auth read -i 6 -f json | jq .config.require_email_verified
  false
  $ pfa -c config.json auth update -i 7 --require-verified-email
  $ pfa -c config.json auth read -i 7 -f json | jq .config.require_email_verified
  true
