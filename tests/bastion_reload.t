Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create bastion resource
  $ pfa -c config.json bastion create --url http://localhost:$BASTION_PORT

Reload with no active connections
  $ curl -sf --unix-socket $BASTION_CTRL_SOCK -X POST http://localhost/reload

#Provision host identity
#  $ pfa -c config.json identity create -n host
#  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
#  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
#  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
#  $ pf -c host.json config --directory $DIRECTORY_URL
#  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
#  $ pf -c host.json accept --invitation=$INVITATION --key host-account
#  $ pf -c host.json login
#
#Start echo server and register with bastion
#  $ socat TCP-LISTEN:1234,reuseaddr,fork EXEC:/bin/cat > echo-server.log 2>&1 &
#  $ ECHO_PID=$!
#  $ pf -c host.json bastion register -p 1234 > register.log 2>&1 &
#  $ BASTION_REGISTER_PID=$!
#  $ sleep 1
#
#Provision user identity
#  $ pfa -c config.json identity create -n user
#  $ USER_ID=$(pfa -c config.json identity list -n user -q)
#  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
#  $ pf -c user.json config --directory $DIRECTORY_URL
#  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
#  $ pf -c user.json accept --invitation=$INVITATION --key user-account
#  $ pf -c user.json login
#
#Verify connection works before reload
#  $ echo "hello" | timeout 2 pf -c user.json bastion connect --url http://localhost:$BASTION_PORT --host host
#  hello
#
#Reload with live registered connection
#  $ curl -sf --unix-socket $BASTION_CTRL_SOCK -X POST http://localhost/reload
#  {"status":"ok"} (no-eol)
#
#Verify connection still works after reload
#  $ echo "hello" | timeout 2 pf -c user.json bastion connect --url http://localhost:$BASTION_PORT --host host
#  hello
#
#Cleanup
#  $ pkill -P -9 $BASTION_REGISTER_PID 2>/dev/null || true
#  $ kill $BASTION_REGISTER_PID 2>/dev/null || true
#  $ kill -TERM $ECHO_PID 2>/dev/null || true
