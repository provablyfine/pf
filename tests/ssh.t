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
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ ssh-keygen -t ed25519 -f user-session -N "" > /dev/null
  $ pf -c user.json login --session-key user-session

User connects to host via pf ssh
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "whoami"
  root
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  User is not authorized to connect to host
  [2]
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  alice

User lists hosts - shell only so far
  $ pf -c user.json hosts
  host    type    username    details
  ------  ------  ----------  ---------
  host    shell   root
  host    shell   alice

Add port-forwarding and command grants
  $ pfa -c config.json grant ssh-port --tag id=device --username root | pfa -c config.json role grant -i $ROLE_ID --add
  $ pfa -c config.json grant ssh-command --tag id=device --username root --cmd /bin/df /bin/ls | pfa -c config.json role grant -i $ROLE_ID --add

User lists hosts - all permission types
  $ pf -c user.json hosts
  host    type     username    details
  ------  -------  ----------  ----------------
  host    shell    root
  host    shell    alice
  host    port     root
  host    command  root        /bin/df, /bin/ls

Local port forwarding (-L) succeeds for root (has port-forwarding permission)
  $ pf -c user.json ssh -L 19901:localhost:22 -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "echo ok"
  ok

Local port forwarding (-L) rejected for alice (shell permission only)
  $ pf -c user.json ssh -L 19902:localhost:22 -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "echo ok"
  User is not authorized to connect to host
  [2]

Remote port forwarding (-R) succeeds for root
  $ pf -c user.json ssh -R 19903:localhost:22 -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "echo ok"
  ok

Add command-only grant for charlie
  $ pfa -c config.json grant ssh-command --tag id=device --username charlie --cmd /bin/true | pfa -c config.json role grant -i $ROLE_ID --add

Command fallback: charlie has command(/bin/true) but not shell — shell cert rejected, command cert accepted
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT charlie@host "/bin/true"

Command fallback fails: /bin/ls not in charlie's allowed command list
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT charlie@host "/bin/ls"
  User is not authorized to connect to host
  [2]

Grant bob a shell with agent and X11 forwarding
  $ pfa -c config.json grant ssh-shell --tag id=device --username bob --permit-agent-forwarding --permit-x11-forwarding | pfa -c config.json role grant -i $ROLE_ID --add

Forwarding capabilities reach the certificate
  $ pf -c user.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  bob
  $ CERT_EXTENSIONS="[.[] | select(.type==\"create-user-certificate\")] | last | .details.extensions | with_entries(select(.value)) | keys_unsorted | join(\" \")"
  $ pfa -c config.json audit-log list --format json | jq -r "$CERT_EXTENSIONS"
  permit_agent_forwarding permit_pty permit_user_rc permit_x11_forwarding

A boundary ceiling caps forwarding capabilities. This was impossible before the
capability model: a ceiling was a boolean gate over username membership, so
permit_agent_forwarding and permit_x11_forwarding always leaked through.
  $ pfa -c config.json boundary create -n capped -d "shell without forwarding"
  $ CAPPED_ID=$(pfa -c config.json boundary list -n capped -q)
  $ pfa -c config.json boundary ceiling -i $CAPPED_ID --set <<EOF
  > - type: ssh
  >   filter: {name: null, tag_list: null, boundary_list: null}
  >   permission:
  >     username_list: null
  >     capability_list: ["shell", "pty", "user-rc"]
  >     command_list: null
  > EOF

Provision a user inside that boundary
  $ pfa -c config.json identity create -n capped-user -b capped
  $ CAPPED_USER_ID=$(pfa -c config.json identity list -n capped-user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a capped-user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $CAPPED_USER_ID)
  $ ssh-keygen -t ed25519 -f capped-account -N "" > /dev/null
  $ pf -c capped.json accept --invitation=$INVITATION --key capped-account
  $ ssh-keygen -t ed25519 -f capped-session -N "" > /dev/null
  $ pf -c capped.json login --session-key capped-session

The very same bob grant now yields a certificate with neither forwarding
  $ pf -c capped.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  bob
  $ pfa -c config.json audit-log list --format json | jq -r "$CERT_EXTENSIONS"
  permit_pty permit_user_rc

The ceiling covers no port-forwarding atom, so that capability is gone too
  $ pf -c capped.json ssh -L 19904:localhost:22 -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "echo ok"
  User is not authorized to connect to host
  [2]

A deny is targeted: it removes only the atoms it covers. Denying X11 alone was
inexpressible before -- the only way to reach a forwarding flag was to deny the
whole shell for that username.
  $ pfa -c config.json boundary create -n targeted -d "no X11 for bob"
  $ TARGETED_ID=$(pfa -c config.json boundary list -n targeted -q)
  $ pfa -c config.json boundary denied -i $TARGETED_ID --set <<EOF
  > - type: ssh
  >   filter: {name: null, tag_list: null, boundary_list: null}
  >   permission:
  >     username_list: ["bob"]
  >     capability_list: ["x11-forwarding"]
  >     command_list: []
  > EOF
  $ pfa -c config.json identity create -n targeted-user -b targeted
  $ TARGETED_USER_ID=$(pfa -c config.json identity list -n targeted-user -q)
  $ pfa -c config.json role member -i $ROLE_ID -a targeted-user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $TARGETED_USER_ID)
  $ ssh-keygen -t ed25519 -f targeted-account -N "" > /dev/null
  $ pf -c targeted.json accept --invitation=$INVITATION --key targeted-account
  $ ssh-keygen -t ed25519 -f targeted-session -N "" > /dev/null
  $ pf -c targeted.json login --session-key targeted-session

bob keeps his shell and his agent forwarding, and loses only X11
  $ pf -c targeted.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT bob@host "whoami"
  bob
  $ pfa -c config.json audit-log list --format json | jq -r "$CERT_EXTENSIONS"
  permit_agent_forwarding permit_pty permit_user_rc

Denying every capability for alice drops only her
  $ pfa -c config.json boundary denied -i $TARGETED_ID --set <<EOF
  > - type: ssh
  >   filter: {name: null, tag_list: null, boundary_list: null}
  >   permission:
  >     username_list: ["alice"]
  >     capability_list: null
  >     command_list: null
  > EOF
  $ pf -c targeted.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  User is not authorized to connect to host
  [2]
  $ pf -c targeted.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT root@host "whoami"
  root
  $ pf -c targeted.json hosts
  host    type     username    details
  ------  -------  ----------  ----------------
  host    shell    root
  host    shell    bob
  host    port     root
  host    command  root        /bin/df, /bin/ls
  host    command  charlie     /bin/true

An "ssh" grant with a wildcard username applies to any username and is
reported as "*", since a wildcard cannot be enumerated
  $ pfa -c config.json role create -n wildcard
  $ WILDCARD_ROLE_ID=$(pfa -c config.json role list -n wildcard -q)
  $ pfa -c config.json role grant -i $WILDCARD_ROLE_ID --set <<EOF
  > - type: ssh
  >   filter: {name: null, tag_list: [{name: id, value: device}], boundary_list: null}
  >   permission:
  >     username_list: null
  >     capability_list: ["shell", "pty"]
  >     command_list: ["/bin/true"]
  > EOF
  $ pfa -c config.json identity create -n wildcard-user -b targeted
  $ WILDCARD_USER_ID=$(pfa -c config.json identity list -n wildcard-user -q)
  $ pfa -c config.json role member -i $WILDCARD_ROLE_ID -a wildcard-user
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $WILDCARD_USER_ID)
  $ ssh-keygen -t ed25519 -f wildcard-account -N "" > /dev/null
  $ pf -c wildcard.json accept --invitation=$INVITATION --key wildcard-account
  $ ssh-keygen -t ed25519 -f wildcard-session -N "" > /dev/null
  $ pf -c wildcard.json login --session-key wildcard-session
  $ pf -c wildcard.json hosts
  host    type     username    details
  ------  -------  ----------  ---------
  host    shell    *
  host    command  *           /bin/true
  $ pf -c wildcard.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT charlie@host "whoami"
  charlie

The boundary deny still applies to the wildcard grant
  $ pf -c wildcard.json ssh -n -o "Hostname=$SSHD_ADDRESS" -o "HostKeyAlias=host" -p $SSHD_PORT alice@host "whoami"
  User is not authorized to connect to host
  [2]
