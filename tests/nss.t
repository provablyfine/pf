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

Provision user identity with unix fields
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ pfa -c config.json identity update -i $USER_ID --unix-username alice
  $ pfa -c config.json role member -i $ROLE_ID -a user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)

User accepts invite and logs in
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

{self} resolves to alice — NSS synthesizes the account on-demand, no pre-existing Unix user
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "echo \$USER"
  alice

NSS-synthesized UID is in the configured range [1000, 60000)
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host \
  >   'uid=$(id -u); [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && echo ok'
  ok

bob has no grant — auth still enforced despite NSS synthesizing any username
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  User is not authorized to connect to host
  [2]

Clear unix: {self} is now unresolvable, connection fails
  $ pfa -c config.json identity update -i $USER_ID --unix-username ""
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  User is not authorized to connect to host
  [2]
