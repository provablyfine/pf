Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects: device tag, role, and {self} grant
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)
  $ pfa -c config.json grant ssh-shell --tag id=device --username '{self}' | pfa -c config.json role grant -i $ROLE_ID --add

Provision host identity and set up SSH
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ pf -c host.json accept --invitation=$INVITATION --key host-account
  $ ssh-keygen -t ed25519 -f host-session -N "" > /dev/null
  $ pf -c host.json login --session-key host-session
  $ pf -c host.json openssh sign-host --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_rsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ecdsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ed25519_key.pub
  $ pf -c host.json openssh user-trusted-keys > $SSHD_KEYS_DIRECTORY/user-ca.pub
  $ podman exec $SSHD_CONTAINER_ID pkill -HUP sshd

Provision user identity: joining the role auto-assigns a standalone unix_username
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a user
  $ UNIX_USERNAME=$(pfa -c config.json identity read -i $USER_ID -f json | jq -r .unix_username)
  $ echo $UNIX_USERNAME
  u1
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)

User accepts invite and logs in
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

{self} resolves to the auto-assigned unix_username — NSS synthesizes the account on-demand, no pre-existing Unix user
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT $UNIX_USERNAME@host "echo \$USER"
  u1

NSS-synthesized UID is the arithmetic offset from the host's configured unix_min_uid (1000 + 1 = 1001)
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT $UNIX_USERNAME@host \
  >   'echo "uid=$(id -u) gid=$(id -g)"'
  uid=1001 gid=1001

Reverse lookup: getent passwd on the synthesized uid resolves back to the same username
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT $UNIX_USERNAME@host \
  >   'getent passwd $(id -u) | cut -d: -f1'
  u1

NSS does not synthesize accounts for names outside the u<hex> pattern — it lets them fall through
  $ podman exec $SSHD_CONTAINER_ID getent passwd notausername
  [2]

bob has no grant, and "bob" is not a synthesizable username either — auth is still enforced
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  User is not authorized to connect to host
  [2]

Clear unix_username: {self} is now unresolvable, connection fails
  $ pfa -c config.json identity update -i $USER_ID --unix-username ""
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT $UNIX_USERNAME@host "whoami"
  User is not authorized to connect to host
  [2]
