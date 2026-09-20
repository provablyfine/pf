Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)
  $ ROOT_ID=$(pfa -c config.json identity list -n root -q)
  $ source $TESTDIR/access-control-identity-fixture.sh
  .* (re)

No identity permission. Try to use them.
  $ pfa -c user1.json identity list
  $ pfa -c user1.json identity read -i 1
  No identity found
  [2]
  $ pfa -c user1.json identity create -n hello
  Not allowed to create identity
  [2]
  $ pfa -c user1.json identity delete -i $ROOT_ID
  Identity not found
  [2]
  $ pfa -c user1.json identity tag -i $ROOT_ID -a $PERSON_ID
  Identity not found
  [2]
  $ pfa -c user1.json identity tag -i $ROOT_ID -d $PERSON_ID
  Identity not found
  [2]
  $ pfa -c user1.json identity update -i $ROOT_ID -n root1
  Identity not found
  [2]
