Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects
  $ pf admin tag create -n id -v device
  $ DEVICE_TAG_ID=$(pf admin tag list -n id -v device -q)
  $ pf admin role create -n role
  $ ROLE_ID=$(pf admin role list -n role -q)
  $ pf admin grant ssh --tag id=device --username root | pf admin role grant -i $ROLE_ID --add
  $ pf admin grant ssh --tag id=device --username alice | pf admin role grant -i $ROLE_ID --add

Provision new host
  $ pf admin identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(pf admin identity list -n host -q)
  $ INVITATION=$(pf admin identity invite --manual -i $HOST_ID)
  $ echo $INVITATION
  .* (re)

New host starts
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/directory
  $ pf -c host.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ pf -c host.json accept --invitation=$INVITATION  --key host-account
  $ ssh-keygen -t ed25519 -f host-session -N "" > /dev/null
  $ pf -c host.json login --session-key host-session

New host SSH setup
  $ pf -c host.json openssh sign-host --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_rsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ecdsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ed25519_key.pub
  $ pf -c host.json openssh user-trusted-keys > $SSHD_KEYS_DIRECTORY/user-ca.pub
  $ podman exec $SSHD_CONTAINER_ID pkill -HUP sshd

Provision new user
  $ pf admin identity create -n user
  $ USER_ID=$(pf admin identity list -n user -q)
  $ pf admin role member -i $ROLE_ID -a user
# XXX: test $USER_ID above
  $ INVITATION=$(pf admin identity invite --manual -i $USER_ID)
  $ echo $INVITATION
  .* (re)

User accepts invite and logs in
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/directory
  $ pf -c user.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

User attempts to log into host
  $ IDBCTL=$(whereis -b pf |cut -d' ' -f2)
  $ pf -c user.json openssh known-hosts > ./known_hosts
  $ cat <<EOF > ssh_config
  > Match Exec "pf -c user.json openssh auth --host %h --user %r --known-hosts ./known_hosts --host-krl ./host.krl --identity-file ./device.name.pub --certificate-file ./device.name.cert"
  >      KnownHostsCommand /usr/bin/cat ./known_hosts
  >      Hostname 127.0.0.1
  >      HostKeyAlias host
  >      Port $SSHD_PORT
  > EOF
  $ ssh -n -F ./ssh_config root@host "whoami"
  root
  $ ssh -n -F ./ssh_config bob@host "whoami"
  bob@127.0.0.1: Permission denied (publickey).\r (esc)
  [255]
  $ ssh -n -F ./ssh_config alice@host "whoami"
  alice
