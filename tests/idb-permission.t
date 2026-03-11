Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create tag
  $ idbctl admin tag create -n env -v dev

Create role
  $ idbctl admin role create -n test
  $ ROLE_ID=$(idbctl admin role list -n test -q)

Find root id
  $ IDENTITY_ID=$(idbctl admin identity list -n root -q)

Add invalid permissions to role
  $ idbctl admin grant identity --create-allowed --name unknown | idbctl admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ idbctl admin grant identity --create-allowed --name unknown --tag hoy=bar| idbctl admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ idbctl admin grant identity --create-allowed --name unknown --boundary unknown | idbctl admin role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]

Add a real permission to role
  $ idbctl admin grant identity --create-allowed --name root | idbctl admin role grant -i $ROLE_ID --add
  $ idbctl admin grant identity --create-allowed --boundary root | idbctl admin role grant -i $ROLE_ID --add
  $ idbctl admin grant identity --create-allowed --tag env=dev | idbctl admin role grant -i $ROLE_ID --add
  $ idbctl admin role read -i $ROLE_ID
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
