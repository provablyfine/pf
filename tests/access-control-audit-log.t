Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Setup user1 in a role with no grants
  $ source $TESTDIR/access-control-identity-fixture.sh
  .* (re)
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)

Without audit-log grant, user1 cannot read audit log
  $ pfa -c user1.json audit-log list
  Not allowed to read audit log
  [2]

Add audit-log read grant to the role
  $ pfa -c config.json grant audit-log --read | pfa -c config.json role grant -i $ROLE_ID --add

With audit-log grant, user1 can read audit log
  $ pfa -c user1.json audit-log list --quiet | wc -l
  .* (re)
