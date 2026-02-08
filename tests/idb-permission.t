Initialize server and login
  $ bash $TESTDIR/fixture.sh

Create tag
  $ idbctl admin tag create -n env -v dev

Create role
  $ idbctl admin role create -n test
  $ ROLE_ID=$(idbctl admin role list -n test -q)

Find root id
  $ IDENTITY_ID=$(idbctl admin identity list -n root -q)

Add invalid permissions to role
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:haha/hoy:*
  Unable to update role. Request validation error.
  [2]
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:name/unknown:*
  Unable to update role. Permission field invalid. Identity cannot be found.
  [2]
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:tag/hoy:*
  Unable to update role. Permission field invalid. Expected: name=value.
  [2]
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:tag/hoy=bar:*
  Unable to update role. Permission field invalid. Tag cannot be found.
  [2]
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:tag/env=prod:*
  Unable to update role. Permission field invalid. Tag cannot be found.
  [2]
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:boundary/unknown:*
  Unable to update role. Permission field invalid. Boundary cannot be found.
  [2]

Add a real permission to role
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:name/root:*
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:boundary/root:*
  $ idbctl admin role permission -i $ROLE_ID -a identity:create:tag/env=dev:*
  $ idbctl admin role read -i $ROLE_ID
  id           2
  name         test
  description
  permission   identity:create:name/root:*
  permission   identity:create:boundary/root:*
  permission   identity:create:tag/env=dev:*
