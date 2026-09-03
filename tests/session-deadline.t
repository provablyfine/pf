Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)
  $ pfa -c config.json grant ssh --tag id=device --username root --capability shell pty user-rc | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh --tag id=device --username alice --capability shell pty user-rc --max-session-ttl 3600 | pfa -c config.json role grant -i $ROLE_ID --add

Provision new host
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
  $ echo $INVITATION
  .* (re)

New host starts
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ pf -c host.json accept --invitation=$INVITATION  --key host-account
  $ ssh-keygen -t ed25519 -f host-session -N "" > /dev/null
  $ pf -c host.json login --session-key host-session

New host SSH setup
  $ pf -c host.json openssh sign-host --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_rsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ecdsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ed25519_key.pub
  $ pf -c host.json openssh user-trusted-keys > $SSHD_KEYS_DIRECTORY/user-ca.pub
  $ podman exec $SSHD_CONTAINER_ID pkill -HUP sshd

Provision new user
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

Root has unbounded shell sessions
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "whoami"
  root
  $ podman exec $SSHD_CONTAINER_ID sh -c "grep -c 'session_deadline decoded' /var/log/pf/session-deadline.log || true"
  0

Alice has bounded shell sessions
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  alice
  $ podman exec $SSHD_CONTAINER_ID grep -o "session_deadline decoded connection_id=[0-9a-f-]* deadline=[0-9]*" /var/log/pf/session-deadline.log
  session_deadline decoded connection_id=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} deadline=[0-9]+ (re)
