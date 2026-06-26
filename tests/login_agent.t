Initialize with file account key
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account

Login without --session-key: SSH agent is available, fingerprint stored
  $ pf -c config.json login
  $ python3 -c "import json; c=json.load(open('config.json')); fp=c.get('session_key_fingerprint'); print(fp is not None, c.get('session_key_file'), c.get('session_key_pem'))"
  True None None
  $ stat -c "%a" config.json
  600

Verify subsequent command works with agent session
  $ pfa -c config.json auth list -q
  1
