Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

Create bastion resource
  $ pfa -c config.json bastion create --url $BASTION_URL

Check bastion is alive before anything
  $ curl -si --unix-socket $BASTION_CTRL_SOCK -X POST http://localhost/ping
  HTTP/1.1 200 OK\r (esc)
  \r (esc)

No active connections
  $ curl -s --unix-socket $BASTION_CTRL_SOCK http://localhost/registered
  {"clients": []} (no-eol)

Provision host identity
  $ pfa -c config.json identity create -n host
  $ HOST_ID=$(pfa -c config.json identity list -n host -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $HOST_ID)
  $ ssh-keygen -t ed25519 -f host-account -N "" > /dev/null
  $ pf -c host.json accept --invitation=$INVITATION --key host-account
  $ pf -c host.json login

Start echo server and register with bastion
  $ socat TCP-LISTEN:1234,reuseaddr,fork EXEC:/bin/cat > echo-server.log 2>&1 &
  $ ECHO_PID=$!
  $ pf -c host.json bastion register --socket-path $BASTION_MAIN_SOCK -p 1234 > register.log 2>&1 &
  $ BASTION_REGISTER_PID=$!
  $ sleep 1

Check bastion is still alive
  $ curl -si --unix-socket $BASTION_CTRL_SOCK -X POST http://localhost/ping
  HTTP/1.1 200 OK\r (esc)
  \r (esc)

List registered connection
  $ curl -s --unix-socket $BASTION_CTRL_SOCK http://localhost/registered | jq
  {
    "clients": [
      {
        "tenant_id": 1,
        "name": "host",
        "connected_since": [^,]+, (re)
        "duration_seconds": [^,]+, (re)
        "bytes_rx": 0,
        "bytes_tx": 0,
        "nconnections": 0,
        "connections": []
      }
    ]
  }

Provision user identity
  $ pfa -c config.json identity create -n user
  $ USER_ID=$(pfa -c config.json identity list -n user -q)
  $ INVITATION=$(pfa -c config.json identity invite --manual -i $USER_ID)
  $ ssh-keygen -t ed25519 -f user-account -N "" > /dev/null
  $ pf -c user.json accept --invitation=$INVITATION --key user-account
  $ pf -c user.json login

Verify connection works before restart
  $ echo "hello" | timeout 2 pf -c user.json bastion connect --socket-path $BASTION_MAIN_SOCK --url $BASTION_URL --host host
  hello

Check bastion is still alive
  $ curl -si --unix-socket $BASTION_CTRL_SOCK -X POST http://localhost/ping
  HTTP/1.1 200 OK\r (esc)
  \r (esc)

Check that registered connection is still here
  $ curl -s --unix-socket $BASTION_CTRL_SOCK http://localhost/registered | jq
  {
    "clients": [
      {
        "tenant_id": 1,
        "name": "host",
        "connected_since": [^,]+, (re)
        "duration_seconds": [^,]+, (re)
        "bytes_rx": 6,
        "bytes_tx": 6,
        "nconnections": 0,
        "connections": []
      }
    ]
  }

Restart bastion via systemctl — systemd handles fdstore donation + recovery
  $ podman exec $CONTAINER_ID systemctl restart pf-bastion
  $ sleep 1

Verify registered connection still here after restart
  $ curl -s --unix-socket $BASTION_CTRL_SOCK http://localhost/registered | jq
  {
    "clients": [
      {
        "tenant_id": 1,
        "name": "host",
        "connected_since": [^,]+, (re)
        "duration_seconds": [^,]+, (re)
        "bytes_rx": 6,
        "bytes_tx": 6,
        "nconnections": 0,
        "connections": []
      }
    ]
  }

Verify connection still works across exec boundary
  $ echo "hello" | timeout 2 pf -c user.json bastion connect --socket-path $BASTION_MAIN_SOCK --url $BASTION_URL --host host
  hello

Cleanup
  $ kill $BASTION_REGISTER_PID 2>/dev/null || true
  $ kill -TERM $ECHO_PID 2>/dev/null || true
