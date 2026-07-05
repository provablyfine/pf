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

Acme user cannot read root tenant record (ownership filter returns 404)
  $ pfa -c acme.json tenant get -i 1
  Tenant 1 not found
  [2]

Acme user sees only its own tags, not tags from root tenant
  $ pfa -c acme.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   acme-only

Root user sees only its own tags, not tags from other tenants
  $ pfa -c config.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   root-only

Acme user sees only its own identities, not root from root tenant
  $ pfa -c acme.json identity list -q
  1

Scenario 2: two sibling child tenants cannot access each other

Acme cannot read beta tenant record
  $ pfa -c acme.json tenant get -i 3
  Tenant 3 not found
  [2]

Beta cannot read acme tenant record
  $ pfa -c beta.json tenant get -i 2
  Tenant 2 not found
  [2]

Beta user sees only beta tags, not acme
  $ pfa -c beta.json tag list
    id  name    value
  ----  ------  ---------
     1  scope   beta-only

Beta user sees only beta identities, not acme
  $ pfa -c beta.json identity list -q
  1

Child tenant (acme) cannot create sub-tenants (denied_list blocks it)
  $ pfa -c acme.json tenant create --name sub-acme --display-name "Sub Acme"
  Not allowed to create tenant
  [2]

Child tenant (acme) CAN use SSH grants (pf hosts returns accessible hosts)
  $ pfa -c acme.json tag create -n type -v device
  $ DEVICE_TAG=$(pfa -c acme.json tag list -n type -v device -q)
  $ pfa -c acme.json identity create -n acme-host -t $DEVICE_TAG
  $ pfa -c acme.json role create -n ssh-role
  $ ROLE_ID=$(pfa -c acme.json role list -n ssh-role -q)
  $ pfa -c acme.json grant ssh-shell --tag type=device --username alice | pfa -c acme.json role grant -i $ROLE_ID --add
  $ pfa -c acme.json identity create -n user1
  $ USER1_ID=$(pfa -c acme.json identity list -n user1 -q)
  $ pfa -c acme.json role member -i $ROLE_ID -a user1
  $ INVITATION=$(pfa -c acme.json identity invite --manual -i $USER1_ID)
  $ ssh-keygen -t ed25519 -f acme-user1 -N "" > /dev/null
  $ pf -c acme-user1.json accept --invitation=$INVITATION --key acme-user1
  $ ssh-keygen -t ed25519 -f acme-user1-session -N "" > /dev/null
  $ pf -c acme-user1.json login --session-key acme-user1-session
  $ pf -c acme-user1.json hosts
  host       type    username    details
  ---------  ------  ----------  ---------
  acme-host  shell   alice
