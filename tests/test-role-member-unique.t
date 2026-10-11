Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a role
  $ ROLE_ID=$(pfa -c config.json role create -n test-role)

Create an identity
  $ pfa -c config.json identity create -n test-identity
  [0-9]+ (re)

Add the identity as a member to the role
  $ pfa -c config.json role member -i $ROLE_ID -a test-identity

Verify the member was added
  $ pfa -c config.json role read -i $ROLE_ID | grep member
  member *test-identity (re)

Attempt to add the same identity again should fail
  $ pfa -c config.json role member -i $ROLE_ID -a test-identity
  .* (re)
  [2]
