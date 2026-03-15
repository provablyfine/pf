Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_ID=$(pf admin identity list -n root -q)
  $ source $TESTDIR/access-control-identity-fixture.sh
  .* (re)

No identity permission. Try to use them.
  $ pf -c user1.json admin identity list
  $ pf -c user1.json admin identity read -i 1
  No identity found
  [2]
  $ pf -c user1.json admin identity create -n hello
  Unable to create identity. Not allowed to create identity
  [2]
  $ pf -c user1.json admin identity delete -i $ROOT_ID
  Unable to delete identity. Not allowed to delete identity
  [2]
  $ pf -c user1.json admin identity tag -i $ROOT_ID -a $PERSON_ID
  Unable to update identity. Not allowed to update tag.
  [2]
  $ pf -c user1.json admin identity tag -i $ROOT_ID -d $PERSON_ID
  Unable to update identity. Not allowed to update tag.
  [2]
  $ pf -c user1.json admin identity update -i $ROOT_ID -n root1
  Unable to update identity. Not allowed to update identity field.
  [2]
