Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_ID=$(pfa identity list -n root -q)
  $ source $TESTDIR/access-control-identity-fixture.sh
  .* (re)

No identity permission. Try to use them.
  $ pfa -c user1.json identity list
  $ pfa -c user1.json identity read -i 1
  No identity found
  [2]
  $ pfa -c user1.json identity create -n hello
  Unable to create identity. Not allowed to create identity
  [2]
  $ pfa -c user1.json identity delete -i $ROOT_ID
  Unable to delete identity. Not allowed to delete identity
  [2]
  $ pfa -c user1.json identity tag -i $ROOT_ID -a $PERSON_ID
  Unable to update identity. Not allowed to update tag.
  [2]
  $ pfa -c user1.json identity tag -i $ROOT_ID -d $PERSON_ID
  Unable to update identity. Not allowed to update tag.
  [2]
  $ pfa -c user1.json identity update -i $ROOT_ID -n root1
  Unable to update identity. Not allowed to update identity field.
  [2]
