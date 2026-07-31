Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Set up a device host identity that grants {self} shell access
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID

Trigger 1: member added to a role that already grants {self}
  $ pfa -c config.json role create -n role1
  $ ROLE1_ID=$(pfa -c config.json role list -n role1 -q)
  $ pfa -c config.json grant ssh-shell --tag id=device --username '{self}' | pfa -c config.json role grant -i $ROLE1_ID --add
  $ pfa -c config.json identity create -n alice
  $ ALICE_ID=$(pfa -c config.json identity list -n alice -q)
  $ pfa -c config.json role member -i $ROLE1_ID -a alice
  $ pfa -c config.json identity read -i $ALICE_ID
  id             [0-9]+ (re)
  name           alice
  boundary       root
  unix_username  u1

Trigger 2: {self} granted to a role that already has a member with no unix_username
  $ pfa -c config.json role create -n role2
  $ ROLE2_ID=$(pfa -c config.json role list -n role2 -q)
  $ pfa -c config.json identity create -n bob
  $ BOB_ID=$(pfa -c config.json identity list -n bob -q)
  $ pfa -c config.json role member -i $ROLE2_ID -a bob
  $ pfa -c config.json identity read -i $BOB_ID
  id        [0-9]+ (re)
  name      bob
  boundary  root
  $ pfa -c config.json grant ssh-shell --tag id=device --username '{self}' | pfa -c config.json role grant -i $ROLE2_ID --add
  $ pfa -c config.json identity read -i $BOB_ID
  id             [0-9]+ (re)
  name           bob
  boundary       root
  unix_username  u2

A member who already has a unix_username keeps it (not reassigned)
  $ pfa -c config.json identity create -n carol
  $ CAROL_ID=$(pfa -c config.json identity list -n carol -q)
  $ pfa -c config.json identity update -i $CAROL_ID --unix-username carol
  $ pfa -c config.json role member -i $ROLE1_ID -a carol
  $ pfa -c config.json identity read -i $CAROL_ID
  id             [0-9]+ (re)
  name           carol
  boundary       root
  unix_username  carol
