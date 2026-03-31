Initialize root tenant and create a root-specific tag
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ pfa -c config.json tag create -n scope -v root-only

Create and initialize child tenant "acme"
  $ pfa -c config.json tenant create --name acme --display-name "Acme Corp"
  .* (re)
  .* (re)
  .* (re)
  $ ssh-keygen -t ed25519 -f acme-account -N "" > /dev/null
  $ pfa -c acme.json initialize http://127.0.0.1:$API_PORT/pf/t/acme/directory --key acme-account
  $ ssh-keygen -t ed25519 -f acme-session -N "" > /dev/null
  $ pfa -c acme.json login --session-key acme-session
  $ pfa -c acme.json tag create -n scope -v acme-only

Create and initialize child tenant "beta"
  $ pfa -c config.json tenant create --name beta --display-name "Beta Corp"
  .* (re)
  .* (re)
  .* (re)
  $ ssh-keygen -t ed25519 -f beta-account -N "" > /dev/null
  $ pfa -c beta.json initialize http://127.0.0.1:$API_PORT/pf/t/beta/directory --key beta-account
  $ ssh-keygen -t ed25519 -f beta-session -N "" > /dev/null
  $ pfa -c beta.json login --session-key beta-session
  $ pfa -c beta.json tag create -n scope -v beta-only

Scenario 1: child tenant cannot see owner tenant

Acme user sees only its own tenant in the tenant list, not root or beta
  $ pfa -c acme.json tenant list -q
  2

Beta user sees only its own tenant in the tenant list, not root or acme
  $ pfa -c beta.json tenant list -q
  3

Root user sees itself and all owned child tenants
  $ pfa -c config.json tenant list -q
  1
  2
  3

Acme user cannot read root's tenant record (ownership filter returns 404)
  $ pfa -c acme.json tenant get -i 1
  Tenant 1 not found
  [2]

Acme user sees only its own tags, not root's
  $ pfa -c acme.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   acme-only

Root user sees only its own tags, not acme's or beta's
  $ pfa -c config.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   root-only

Acme user sees only its own identities, not root's
  $ pfa -c acme.json identity list -q
  1

Scenario 2: two sibling child tenants cannot access each other

Acme cannot read beta's tenant record
  $ pfa -c acme.json tenant get -i 3
  Tenant 3 not found
  [2]

Beta cannot read acme's tenant record
  $ pfa -c beta.json tenant get -i 2
  Tenant 2 not found
  [2]

Beta user sees only beta's tags, not acme's
  $ pfa -c beta.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   beta-only

Beta user sees only beta's identities, not acme's
  $ pfa -c beta.json identity list -q
  1

Child tenant (acme) cannot create sub-tenants (ceiling blocks it)
  $ pfa -c acme.json tenant create --name sub-acme --display-name "Sub Acme"
  Unable to create tenant: .* (re)
  [2]

Scenario 3: beta credentials rejected by acme's API (cross-auth failure at login)

  $ pf -c cross.json config --directory http://127.0.0.1:$API_PORT/pf/t/acme/directory
  $ jq --arg ak "beta-account" '. + {"account_key": $ak}' cross.json > cross2.json
  $ pf -c cross2.json login --session-key beta-session
  Unable to login successfully: .* (re)
  [2]

Scenario 4: frankenstein config (acme session keys, beta directory) is rejected by beta

  $ pf -c beta-dir.json config --directory http://127.0.0.1:$API_PORT/pf/t/beta/directory
  $ jq -s '.[0] + {"directory_url": .[1].directory_url, "directory": .[1].directory}' acme.json beta-dir.json > frankenstein.json
  $ pfa -c frankenstein.json identity list
  Unable to find identity .* (re)
  [2]
  $ pfa -c frankenstein.json tag list
  Unable to find tags.* (re)
  [2]
  $ pfa -c frankenstein.json tenant list
  Unable to list tenants: .* (re)
  [2]
