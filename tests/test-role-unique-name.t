Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a role
  $ ROLE_ID=$(pfa -c config.json role create -n test-role)
  $ pfa -c config.json role read -i $ROLE_ID | head -3
  id           .* (re)
  name         test-role
  description

Attempt to create another role with the same name should fail
  $ pfa -c config.json role create -n test-role
  .* (re)
  [2]
