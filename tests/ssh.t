Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create admin objects
  $ pfa -c config.json tag create -n id -v device
  $ DEVICE_TAG_ID=$(pfa -c config.json tag list -n id -v device -q)
  $ pfa -c config.json role create -n role
  $ ROLE_ID=$(pfa -c config.json role list -n role -q)
  $ pfa -c config.json grant ssh-shell --tag id=device --username root | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh-shell --tag id=device --username alice | pfa -c config.json role grant -i $ROLE_ID --add

Provision new host
  $ pfa -c config.json identity create -n host -t $DEVICE_TAG_ID
  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
  $ echo $INVITATION
  .* (re)

New host starts
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
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
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a user
# XXX: test $USER_ID above
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
  $ echo $INVITATION
  .* (re)

User accepts invite and logs in
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ pf -c user.json config --directory $DIRECTORY_URL
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

User connects to host via pf ssh
  $ pf -c user.json ssh -n -o "Hostname=127.0.0.1" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "whoami"
  root
  $ pf -c user.json ssh -n -o "Hostname=127.0.0.1" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  User is not authorized to connect to host
  [2]
  $ pf -c user.json ssh -n -o "Hostname=127.0.0.1" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  alice

User lists hosts — shell only so far
  $ pf -c user.json hosts
  host	shell

Add port-forwarding and command grants
  $ pfa -c config.json grant ssh-port-forwarding --tag id=device --username root | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh-command --tag id=device --username root --command /bin/df --command /bin/ls | pfa -c config.json role grant -i $ROLE_ID --add

User lists hosts — all permission types
  $ pf -c user.json hosts
  host	shell
  host	port
  host	command	/bin/df
  host	command	/bin/ls
