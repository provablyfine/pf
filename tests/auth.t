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
  tag_id_list

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
  tag_id_list

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
  id           3
  name         google
  type         oidc
  description
  enabled      True
  created_at   .* (re)
  tag_id_list
  issuer       https://accounts.google.com
  client_id    my-client-id

Create an oidc auth config without issuer (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --client-id my-client-id 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --issuer

Create an oidc auth config without client-id (should fail)
  $ pfa -c config.json auth create oidc -n bad-oidc --issuer https://accounts.google.com 2>&1 | grep "error:"
  pfa auth create oidc: error: the following arguments are required: --client-id

Update auth config name
  $ pfa -c config.json auth update http_sig -i 2 --name corp-http-sig
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description
  enabled      True
  created_at   .* (re)
  tag_id_list

Update auth config description
  $ pfa -c config.json auth update http_sig -i 2 --description "Corporate HTTP signature auth"
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)
  tag_id_list

Disable an auth config
  $ pfa -c config.json auth update http_sig -i 2 --disable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      False
  created_at   .* (re)
  tag_id_list

Re-enable an auth config
  $ pfa -c config.json auth update http_sig -i 2 --enable
  $ pfa -c config.json auth read -i 2
  id           2
  name         corp-http-sig
  type         http_sig
  description  Corporate HTTP signature auth
  enabled      True
  created_at   .* (re)
  tag_id_list

Update oidc params
  $ pfa -c config.json auth update oidc -i 3 --issuer https://login.microsoftonline.com/common --client-id other-client-id
  $ pfa -c config.json auth read -i 3
  id           3
  name         google
  type         oidc
  description
  enabled      True
  created_at   .* (re)
  tag_id_list
  issuer       https://login.microsoftonline.com/common
  client_id    other-client-id

Public discovery endpoint returns correct data for http_sig
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/auth/default | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['name'], d['type'], d['params'])"
  default http_sig {}

Public discovery endpoint returns correct data for oidc
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/auth/google | python3 -c "import sys,json; d=json.load(sys.stdin); p=d['params']; print(d['name'], d['type'], p['issuer'], p['client_id'])"
  google oidc https://login.microsoftonline.com/common other-client-id

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
  tag_id_list
  authorization_endpoint  https://github.com/login/oauth/authorize
  client_id               my-app

Create an oauth2-github auth config without client-secret (should fail)
  $ pfa -c config.json auth create oauth2-github -n bad-oauth2 --client-id my-app 2>&1 | grep "error:"
  pfa auth create oauth2-github: error: the following arguments are required: --client-secret

Public discovery endpoint returns oauth2-github data without client_secret
  $ curl -s http://127.0.0.1:$API_PORT/pf/t/root/auth/corp-oauth2 | python3 -c "import sys,json; d=json.load(sys.stdin); p=d['params']; print(d['name'], d['type'], p['authorization_endpoint'], p['client_id'])"
  corp-oauth2 oauth2-github https://github.com/login/oauth/authorize my-app

Delete the oauth2 auth config
  $ pfa -c config.json auth delete -i 4

Public discovery endpoint returns 404 for unknown name
  $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$API_PORT/pf/t/root/auth/nonexistent
  404

Public discovery endpoint returns 404 for disabled auth config
  $ pfa -c config.json auth update oidc -i 3 --disable
  $ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$API_PORT/pf/t/root/auth/google
  404
  $ pfa -c config.json auth update oidc -i 3 --enable

Read a non-existent auth config
  $ pfa -c config.json auth read -i 999
  Auth config not found
  [2]

Update a non-existent auth config
  $ pfa -c config.json auth update http_sig -i 999 --name whatever
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
