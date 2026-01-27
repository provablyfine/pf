Initialize server and login
  $ bash $TESTDIR/fixture.sh

Create role
  $ idbctl admin role create -n role
  $ ROLE_ID=$(idbctl admin role list -n role -q)

Create identity
  $ idbctl admin identity create -n user 
  $ USER_ID=$(idbctl admin identity list -n user -q)
  $ INVITATION=$(idbctl admin identity invite -i $USER_ID --manual)

Add identity to role
  $ idbctl admin role member -i $ROLE_ID -a user

New user accepts invitation and logs in
  $ DIRECTORY_URL=http://127.0.0.1:$SERVER_PORT/idb/directory
  $ idbctl -c user.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f user -N "" > /dev/null
  $ idbctl -c user.json accept --invitation $INVITATION --key user
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ idbctl -c user.json login --session-key user-session

New user tries to list but no read permission, so nothing shown
  $ idbctl -c user.json admin identity list
  $ idbctl -c user.json admin boundary list
  $ idbctl -c user.json admin role list
  $ idbctl -c user.json admin tag list
  $ idbctl -c user.json admin identity read -i 1
  No identity found
  [2]
  $ idbctl -c user.json admin boundary read -i 1
  No boundary found
  [2]
  $ idbctl -c user.json admin role read -i 1
  No role found
  [2]

New user tries to create but no create permission
  $ idbctl -c user.json admin identity create -n hello
  Unable to create identity. Not allowed to create identity
  [2]

