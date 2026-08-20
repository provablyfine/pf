Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a role
  $ pfa -c config.json role create -n test-role
  $ ROLE_ID=$(pfa -c config.json role list -n test-role -q)

Create an identity
  $ pfa -c config.json identity create -n test-identity
  $ IDENTITY_ID=$(pfa -c config.json identity list -n test-identity -q)

Add the identity as a member to the role
  $ pfa -c config.json role add-members -i $ROLE_ID -m $IDENTITY_ID

Verify the member was added
  $ pfa -c config.json role read -i $ROLE_ID | grep member_id_list
  member_id_list   .* (re)

Attempt to add the same identity again should fail
  $ pfa -c config.json role add-members -i $ROLE_ID -m $IDENTITY_ID
  .* (re)
  [2]
