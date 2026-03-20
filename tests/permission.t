Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create tag
  $ pfa -c config.json tag create -n env -v dev

Create role
  $ pfa -c config.json role create -n test
  $ ROLE_ID=$(pfa -c config.json role list -n test -q)

Find root id
  $ IDENTITY_ID=$(pfa -c config.json identity list -n root -q)

Add invalid permissions to role
  $ pfa -c config.json grant identity --create-allowed --name unknown | pfa -c config.json role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pfa -c config.json grant identity --create-allowed --name unknown --tag hoy=bar| pfa -c config.json role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]
  $ pfa -c config.json grant identity --create-allowed --name unknown --boundary unknown | pfa -c config.json role grant -i $ROLE_ID --add
  Grant specification is invalid
  [2]

Add a real permission to role
  $ pfa -c config.json grant identity --create-allowed --name root | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant identity --create-allowed --boundary root | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant identity --create-allowed --tag env=dev | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json role read -i $ROLE_ID
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
