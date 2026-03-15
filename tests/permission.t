Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create tag
  $ pfa tag create -n env -v dev

Create role
  $ pfa role create -n test
  $ ROLE_ID=$(pfa role list -n test -q)

Find root id
  $ IDENTITY_ID=$(pfa identity list -n root -q)

Add invalid permissions to role
  $ pfa grant identity --create-allowed --name unknown | pfa role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pfa grant identity --create-allowed --name unknown --tag hoy=bar| pfa role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pfa grant identity --create-allowed --name unknown --boundary unknown | pfa role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]

Add a real permission to role
  $ pfa grant identity --create-allowed --name root | pfa role grant -i $ROLE_ID --add
  $ pfa grant identity --create-allowed --boundary root | pfa role grant -i $ROLE_ID --add
  $ pfa grant identity --create-allowed --tag env=dev | pfa role grant -i $ROLE_ID --add
  $ pfa role read -i $ROLE_ID
  id           2
  name         test
  description
  grant        type:       identity
               filter:     name:root
               permission: create
  grant        type:       identity
               filter:     boundary_list:root
               permission: create
  grant        type:       identity
               filter:     tag_list:env=dev
               permission: create
