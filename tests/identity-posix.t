Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a user identity
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)

Set unix_username (manual mode: admin sets it directly)
  $ pfa -c config.json identity update -i $USER_ID --unix-username alice
  $ pfa -c config.json identity read -i $USER_ID
  id             [0-9]+ (re)
  name           user
  boundary       root
  unix_username  alice

Unix username must be unique across identities
  $ pfa -c config.json identity create -n user2
  $ USER2_ID=$(pfa -c config.json identity list -n user2 -q)
  $ pfa -c config.json identity update -i $USER2_ID --unix-username alice
  Identity already exists. "name" and "unix_username" must be unique.
  [2]
  $ pfa -c config.json identity delete -i $USER2_ID

Clear unix_username
  $ pfa -c config.json identity update -i $USER_ID --unix-username ""
  $ pfa -c config.json identity read -i $USER_ID
  id        [0-9]+ (re)
  name      user
  boundary  root

Cleared unix_username is null in JSON output
  $ pfa -c config.json identity list -f json | jq '.[1].unix_username'
  null

Set up for {self} resolution test: host with device tag, role with {self} + literal grant
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)
  $ pfa -c config.json grant ssh-shell --tag id=device --username '{self}' deploy | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json role member -i $ROLE_ID -a user
  $ pfa -c config.json identity update -i $USER_ID --unix-username alice

User accepts invitation and logs in
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

User with unix_username sees {self} resolved to their username in pf hosts
  $ pf -c user.json hosts
  host    type    username    details
  ------  ------  ----------  ---------
  host    shell   alice
  host    shell   deploy

Admin clears unix: {self} entry is dropped, literal username still present
  $ pfa -c config.json identity update -i $USER_ID --unix-username ""
  $ pf -c user.json hosts
  host    type    username    details
  ------  ------  ----------  ---------
  host    shell   deploy
