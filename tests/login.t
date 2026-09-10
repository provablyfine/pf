Initialize with file account key
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account

Login with explicit session key file
  $ ssh-keygen -t ed25519 -f session -N "" > /dev/null
  $ pf -c config.json login --session-key session
  $ python3 -c "import json; c=json.load(open('config.json')); print(c['session_key_file'], c.get('session_key_fingerprint'), c.get('session_key_pem'))"
  session None None
  $ ls -l config.json | cut -c1-10
  -rw-------

Verify subsequent command works with file session key
  $ pfa -c config.json auth list -q
  1

No explicit --session-key and no real ssh-agent
  $ unset SSH_AUTH_SOCK; unset SSH_AGENT_PID
  $ pf -c config.json login
  $ python3 -c "import json; c=json.load(open('config.json')); fp=c.get('session_key_fingerprint'); print(fp is not None, c.get('session_key_file'), c.get('session_key_pem'))"
  True None None

Verify subsequent command works with the oracle-backed session key
  $ pfa -c config.json auth list -q
  1
