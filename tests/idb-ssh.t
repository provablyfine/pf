Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects
  $ idbctl admin tag create -n id -v device
  $ DEVICE_TAG_ID=$(idbctl admin tag list -n id -v device -q)
  $ idbctl admin role create -n role
  $ ROLE_ID=$(idbctl admin role list -n role -q)
  $ idbctl admin role permission -i $ROLE_ID -a identity:ssh-shell:tag/id=device:username/root
  $ idbctl admin role permission -i $ROLE_ID -a identity:ssh-shell:tag/id=device:username/alice

Provision new host
  $ idbctl admin identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(idbctl admin identity list -n host -q)
  $ INVITATION=$(idbctl admin identity invite --manual -i $HOST_ID)
  $ echo $INVITATION
  .* (re)

New host starts
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/idb/directory
  $ idbctl -c host.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ idbctl -c host.json accept --invitation=$INVITATION  --key host-account
  $ ssh-keygen -t ed25519 -f host-session -N "" > /dev/null
  $ idbctl -c host.json login --session-key host-session

New host SSH setup
  $ idbctl -c host.json openssh sign-host --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_rsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ecdsa_key.pub --public-key=$SSHD_KEYS_DIRECTORY/ssh_host_ed25519_key.pub
  $ idbctl -c host.json openssh user-trusted-keys > $SSHD_KEYS_DIRECTORY/user-ca.pub
  $ podman exec $SSHD_CONTAINER_ID pkill -HUP sshd

Provision new user
  $ idbctl admin identity create -n user
  $ USER_ID=$(idbctl admin identity list -n user -q)
  $ idbctl admin role member -i $ROLE_ID -a user
# XXX: test $USER_ID above
  $ INVITATION=$(idbctl admin identity invite --manual -i $USER_ID)
  $ echo $INVITATION
  .* (re)

User accepts invite and logs in
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/idb/directory
  $ idbctl -c user.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ idbctl -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ idbctl -c user.json login --session-key user-session

User attempts to log into host
  $ IDBCTL=$(whereis -b idbctl |cut -d' ' -f2)
  $ idbctl -c user.json openssh known-hosts > ./known_hosts
  $ cat <<EOF > ssh_config
  > Match Exec "idbctl -c user.json openssh auth --host %h --user %r --known-hosts ./known_hosts --host-krl ./host.krl --identity-file ./device.name.pub --certificate-file ./device.name.cert"
  >      KnownHostsCommand /usr/bin/cat ./known_hosts
  >      Hostname 127.0.0.1
  >      HostKeyAlias host
  >      Port $SSHD_PORT
  > EOF
  $ ssh -F ./ssh_config root@host "echo hello"
  hello (no-eol)
