Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create a user identity
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)

Set unix fields with auto-derived uid/gid
  $ pfa -c config.json identity update -i $USER_ID --unix-username alice
  $ pfa -c config.json identity read -i $USER_ID
  id             [0-9]+ (re)
  name           user
  boundary       root
  unix_username  alice
  unix_uid       [0-9]+ (re)
  unix_gid       [0-9]+ (re)

Auto-derived uid is in the configured range [100000, 999999)
  $ pfa -c config.json identity list -f json | jq '.[1].unix_uid | . >= 100000 and . < 999999'
  true

Auto-derived uid equals gid by default (personal group model)
  $ pfa -c config.json identity list -f json | jq '.[1] | .unix_uid == .unix_gid'
  true

Override uid and gid explicitly
  $ pfa -c config.json identity update -i $USER_ID --unix-username alice --unix-uid 100042 --unix-gid 100043
  $ pfa -c config.json identity read -i $USER_ID
  id             [0-9]+ (re)
  name           user
  boundary       root
  unix_username  alice
  unix_uid       100042
  unix_gid       100043

Unix username must be unique across identities
  $ pfa -c config.json identity create -n user2
  $ USER2_ID=$(pfa -c config.json identity list -n user2 -q)
  $ pfa -c config.json identity update -i $USER2_ID --unix-username alice
  Identity already exists. "name", "unix_username", "unix_uid", and "unix_gid" must be unique.
  [2]

Unix uid must be unique (explicit conflict with user's uid 100042)
  $ pfa -c config.json identity update -i $USER2_ID --unix-username bob --unix-uid 100042
  Identity already exists. "name", "unix_username", "unix_uid", and "unix_gid" must be unique.
  [2]
  $ pfa -c config.json identity delete -i $USER2_ID

Clear unix fields
  $ pfa -c config.json identity update -i $USER_ID --unix-username ""
  $ pfa -c config.json identity read -i $USER_ID
  id        [0-9]+ (re)
  name      user
  boundary  root

Cleared unix fields are null in JSON output
  $ pfa -c config.json identity list -f json | jq '.[1] | [.unix_username, .unix_uid, .unix_gid]'
  [
    null,
    null,
    null
  ]

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
