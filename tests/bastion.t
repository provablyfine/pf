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

Port-forwarding grants: root gets a bounded TTL, alice gets none. This
exercises the relay's own deadline enforcement (Phase 3) -- the PAM hook from
Phase 2 never fires for a pure -L/-N connection since no PAM session opens.
  $ pfa -c config.json grant ssh --tag id=device --username root --capability port-forwarding --max-session-ttl 10 | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh --tag id=device --username alice --capability port-forwarding | pfa -c config.json role grant -i $ROLE_ID --add

Root's bounded port-forwarding tunnel through the bastion: reachable once
established, force-closed by the relay once the 10s grant TTL elapses.
-o SessionType=none is ssh's -N equivalent: no remote command is run, so the
session's lifetime is tied only to the transport, not to a remote process
that might finish on its own and confound the deadline assertion below.
  $ pf -c user.json ssh -n -o SessionType=none -L $LOCAL_FORWARD_PORT:127.0.0.1:22 root@host >/dev/null 2>&1 &
  $ ROOT_FWD_PID=$!
  $ sleep 3
  $ kill -0 $ROOT_FWD_PID
  $ sleep 12
  $ kill -0 $ROOT_FWD_PID 2>/dev/null
  [1]
  $ grep -c "deadline reached, closing tunnel" $PF_LOG_DIRECTORY/pf.bastion.register.$REGISTER_PID.log
  1

Alice's unbounded port-forwarding tunnel: absence of a TTL means absence of a
deadline claim, so the relay never schedules a close -- the explicit
backward-compatibility check
  $ pf -c user.json ssh -n -o SessionType=none -L $LOCAL_FORWARD_PORT:127.0.0.1:22 alice@host >/dev/null 2>&1 &
  $ ALICE_FWD_PID=$!
  $ sleep 3
  $ kill -0 $ALICE_FWD_PID
  $ sleep 12
  $ kill -0 $ALICE_FWD_PID
  $ kill $ALICE_FWD_PID 2>/dev/null; true

Shell sessions are enforced at the relay too, not just by the PAM hook. This
sshd container is built with UsePAM no, so nothing host-side can terminate the
session -- if the tunnel dies on time it is the relay's doing. bob gets a
bounded shell grant; the 60s remote command must not outlive the 10s TTL.
  $ pfa -c config.json grant ssh --tag id=device --username bob --capability shell --max-session-ttl 10 | pfa -c config.json role grant -i $ROLE_ID --add
  $ pf -c user.json ssh -n bob@host "sleep 60" >/dev/null 2>&1 &
  $ BOB_SHELL_PID=$!
  $ sleep 3
  $ kill -0 $BOB_SHELL_PID
  $ sleep 12
  $ kill -0 $BOB_SHELL_PID 2>/dev/null
  [1]
The relay logged the close, so the session ended because of the deadline and
not because the remote command finished or the transport broke. Count is 2:
root's port-forwarding tunnel above closed the same way.
  $ grep -c "deadline reached, closing tunnel" $PF_LOG_DIRECTORY/pf.bastion.register.$REGISTER_PID.log
  2

Cleanup
  $ kill $REGISTER_PID 2>/dev/null; true
