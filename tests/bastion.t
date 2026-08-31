Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)
  $ pfa -c config.json grant ssh --tag id=device --username root --capability shell pty user-rc | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh --tag id=device --username alice --capability shell pty user-rc | pfa -c config.json role grant -i $ROLE_ID --add

Create bastion
  $ pfa -c config.json bastion create --url http://127.0.0.1:$FRPS_CONNECT_PORT
  $ BASTION_ID=$(pfa -c config.json bastion list -q)

Provision host identity
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
  $ echo $INVITATION
  .* (re)

Host starts
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ pf -c host.json accept --invitation=$INVITATION --key host-account
  $ ssh-keygen -t ed25519 -f host-session -N "" > /dev/null
  $ pf -c host.json login --session-key host-session

Host SSH setup
  $ pf -c host.json openssh sign-host --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_rsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ecdsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ed25519_key.pub
  $ pf -c host.json openssh user-trusted-keys > $SSHD_KEYS_DIRECTORY/user-ca.pub
  $ podman exec $SSHD_CONTAINER_ID pkill -HUP sshd

Provision user identity
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
  $ echo $INVITATION
  .* (re)

User starts
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

Host registers with bastions
  $ pf -c host.json bastion register --address $SSHD_ADDRESS --port $SSHD_PORT --poll-interval 1 --frps-bind-port $FRPS_BIND_PORT >/dev/null 2>&1 &
  $ REGISTER_PID=$!

Wait for frp client to connect
  $ sleep 2

User connects via bastion
  $ pf -c user.json ssh -n root@host "whoami"
  root
  $ pf -c user.json ssh -n alice@host "whoami"
  alice

Grant a 10s ssh port forwarding to root@host
  $ pfa -c config.json grant ssh --tag id=device --username root --capability port-forwarding --max-session-ttl 10 | pfa -c config.json role grant -i $ROLE_ID --add

Port forwarding for root does not survive more than 10s
  $ pf -c user.json ssh -n -o SessionType=none -L $LOCAL_FORWARD_PORT:127.0.0.1:22 root@host >/dev/null 2>&1 &
  $ ROOT_FWD_PID=$!
  $ sleep 3
  $ kill -0 $ROOT_FWD_PID
  $ sleep 12
  $ kill -0 $ROOT_FWD_PID 2>/dev/null
  [1]
  $ grep -c "deadline reached, closing tunnel" $PF_LOG_DIRECTORY/pf.bastion.register.$REGISTER_PID.log
  1

Grant an unbounded duration ssh port forwarding to alice@host
  $ pfa -c config.json grant ssh --tag id=device --username alice --capability port-forwarding | pfa -c config.json role grant -i $ROLE_ID --add


Port forwarding for alice survives more than 10s
  $ pf -c user.json ssh -n -o SessionType=none -L $LOCAL_FORWARD_PORT:127.0.0.1:22 alice@host >/dev/null 2>&1 &
  $ ALICE_FWD_PID=$!
  $ sleep 3
  $ kill -0 $ALICE_FWD_PID
  $ sleep 12
  $ kill -0 $ALICE_FWD_PID
  $ kill $ALICE_FWD_PID 2>/dev/null; true

Grant a 10s shell to bob@host
  $ pfa -c config.json grant ssh --tag id=device --username bob --capability shell --max-session-ttl 10 | pfa -c config.json role grant -i $ROLE_ID --add
  $ pf -c user.json ssh -n bob@host "sleep 60" >/dev/null 2>&1 &
  $ BOB_SHELL_PID=$!
  $ sleep 3
  $ kill -0 $BOB_SHELL_PID
  $ sleep 12
  $ kill -0 $BOB_SHELL_PID 2>/dev/null
  [1]

Cleanup
  $ kill $REGISTER_PID 2>/dev/null; true
