Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List auth configs (default http_sig config was created at init)
  $ pfa -c config.json auth list
    id  name     type      enabled    description
  ----  -------  --------  ---------  -------------------------------------
     1  default  http_sig  True       Default HTTP signature authentication

List auth configs (quiet)
  $ pfa -c config.json auth list -q
  1

Read the default auth config
  $ pfa -c config.json auth read -i 1
  id           1
  name         default
  type         http_sig
  description  Default HTTP signature authentication
  enabled      True
  created_at   .* (re)
  tags

Create a new http_sig auth config
  $ pfa -c config.json auth create http_sig -n corporate

List auth configs (two now)
  $ pfa -c config.json auth list -q
  1
  2

Read the new auth config
  $ pfa -c config.json auth read -i 2
  id           2
  name         corporate
  type         http_sig
  description
  enabled      True
  created_at   .* (re)
  tags

Create a duplicate auth config
  $ pfa -c config.json auth create http_sig -n default
  Auth config already exists
  [2]

Create an auth config with an integer name (should fail)
  $ pfa -c config.json auth create http_sig -n 42
  Auth config name must not be a pure integer
  [2]

Create an oidc auth config
  $ pfa -c config.json auth create oidc -n google --issuer https://accounts.google.com --client-id my-client-id

Read the oidc auth config
  $ pfa -c config.json auth read -i 3
  id            3
  name          google
  type          oidc
  description
  enabled       True
  created_at    .* (re)
  tags
  issuer        https://accounts.google.com
  client_id     my-client-id
  callback_url  http://127.0.0.1/callback

Create an oidc auth config without issuer (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --client-id my-client-id 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --issuer

Create an oidc auth config without client-id (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --issuer https://accounts.google.com 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --client-id

Update auth config name
  $ pfa -c config.json auth update -i 2 --name corp-http-sig
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description
  enabled      True
  created_at   .* (re)
  tags

Update auth config description
  $ pfa -c config.json auth update -i 2 --description "Corporate HTTP signature auth"
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)
  tags

Disable an auth config
  $ pfa -c config.json auth update -i 2 --disable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      False
  created_at   .* (re)
  tags

Re-enable an auth config
  $ pfa -c config.json auth update -i 2 --enable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)
  tags

Public discovery endpoint returns correct data for http_sig
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/public/auth/default && echo ""
  {"name":"default","description":"Default HTTP signature authentication","config":{"type":"http_sig"}}

Public discovery endpoint returns correct data for oidc
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/public/auth/google && echo ""
  {"name":"google","description":"","config":{"issuer":"https://accounts.google.com","client_id":"my-client-id","client_secret":null,"callback_url":"http://127.0.0.1/callback","type":"oidc"}}

Create an oauth2-github auth config
  $ pfa -c config.json auth create oauth2-github -n corp-oauth2 --client-id my-app --client-secret s3cr3t

Read the oauth2-github auth config (client_secret must not appear)
  $ pfa -c config.json auth read -i 4
  id                      4
  name                    corp-oauth2
  type                    oauth2-github
  description
  enabled                 True
  created_at              .* (re)
  tags
  authorization_endpoint  https://github.com/login/oauth/authorize
  client_id               my-app
  callback_url            .*/auth/oauth2/callback (re)

Create an oauth2-github auth config without client-secret (should fail)
  $ pfa -c config.json auth create oauth2-github -n bad-oauth2 --client-id my-app 2>&1 | grep "error:"
  pfa auth create oauth2-github: error: the following arguments are required: --client-secret

Public discovery endpoint returns oauth2-github data without client_secret
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/public/auth/corp-oauth2 | jq -r ".name,.config.client_id,.config.authorization_endpoint,.config.type"
  corp-oauth2
  my-app
  https://github.com/login/oauth/authorize
  oauth2-github

Delete the oauth2 auth config
  $ pfa -c config.json auth delete -i 4

Public discovery endpoint returns 404 for unknown name
  $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$API_PORT/pf/t/root/public/auth/nonexistent
  404

Public discovery endpoint returns 404 for disabled auth config
  $ pfa -c config.json auth update -i 3 --disable
  $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$API_PORT/pf/t/root/public/auth/google
  404
  $ pfa -c config.json auth update -i 3 --enable

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
  3

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
