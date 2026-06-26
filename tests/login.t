Initialize with file account key
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account

Case 1: login with explicit session key file
  $ ssh-keygen -t ed25519 -f session -N "" > /dev/null
  $ pf -c config.json login --session-key session
  $ python3 -c "import json; c=json.load(open('config.json')); print(c['session_key_file'], c.get('session_key_fingerprint'), c.get('session_key_pem'))"
  session None None
  $ stat -c "%a" config.json
  600

Verify subsequent command works with file session key
  $ pfa -c config.json auth list -q
  1

Case 2: no-agent login, answer Y -> cleartext PEM stored
  $ unset SSH_AUTH_SOCK; unset SSH_AGENT_PID
  $ echo "Y" | pf -c config.json login
  Warning: no SSH agent available. Session key will be stored as cleartext in the config file.
  Store session key as cleartext? [Y/n]:
  $ python3 -c "import json; c=json.load(open('config.json')); print(c.get('session_key_file'), c.get('session_key_fingerprint'), c.get('session_key_pem') is not None)"
  None None True

Verify subsequent command works with PEM session
  $ pfa -c config.json auth list -q
  1

Case 3: no-agent login, answer N -> aborted, existing session preserved
  $ echo "n" | pf -c config.json login
  Warning: no SSH agent available. Session key will be stored as cleartext in the config file.
  Store session key as cleartext? [Y/n]:
  Aborted. Start an SSH agent and retry.
  [2]
