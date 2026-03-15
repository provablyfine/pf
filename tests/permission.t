Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create tag
  $ pf admin tag create -n env -v dev

Create role
  $ pf admin role create -n test
  $ ROLE_ID=$(pf admin role list -n test -q)

Find root id
  $ IDENTITY_ID=$(pf admin identity list -n root -q)

Add invalid permissions to role
  $ pf admin grant identity --create-allowed --name unknown | pf admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pf admin grant identity --create-allowed --name unknown --tag hoy=bar| pf admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pf admin grant identity --create-allowed --name unknown --boundary unknown | pf admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]

Add a real permission to role
  $ pf admin grant identity --create-allowed --name root | pf admin role grant -i $ROLE_ID --add
  $ pf admin grant identity --create-allowed --boundary root | pf admin role grant -i $ROLE_ID --add
  $ pf admin grant identity --create-allowed --tag env=dev | pf admin role grant -i $ROLE_ID --add
  $ pf admin role read -i $ROLE_ID
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
