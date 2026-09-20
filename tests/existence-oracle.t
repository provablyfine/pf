A caller who cannot read an object gets the same answer for an object that exists and one that does not.

Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create an unprivileged identity
  $ pfa -c config.json identity create -n user1
  $ USER1_ID=$(pfa -c config.json identity list -n user1 -q)
  $ INVITATION=$(pfa -c config.json identity invite -i $USER1_ID --manual)
  $ ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
  $ pf -c user1.json accept --invitation=$INVITATION --key user1
  $ ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
  $ pf -c user1.json login --session-key user1-session
  $ ROOT_ID=$(pfa -c config.json identity list -n root -q)
  $ pfa -c config.json tag create -n env -v prod
  $ TAG_ID=$(pfa -c config.json tag list -n env -v prod -q)

Identities
  $ pfa -c user1.json identity delete -i $ROOT_ID
  Identity not found
  [2]
  $ pfa -c user1.json identity delete -i 9999
  Identity not found
  [2]
  $ pfa -c user1.json identity update -i $ROOT_ID -n other
  Identity not found
  [2]
  $ pfa -c user1.json identity update -i 9999 -n other
  Identity not found
  [2]

Tags
  $ pfa -c user1.json tag delete -i $TAG_ID
  Tag does not exist
  [2]
  $ pfa -c user1.json tag delete -i 9999
  Tag does not exist
  [2]
