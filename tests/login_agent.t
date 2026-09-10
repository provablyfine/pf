Initialize with file account key
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account

Login without --session-key: the peer-credential oracle generates and holds
the session key, fingerprint stored (not the key file or PEM)
  $ pf -c config.json login
  $ python3 -c "import json; c=json.load(open('config.json')); fp=c.get('session_key_fingerprint'); print(fp is not None, c.get('session_key_file'), c.get('session_key_pem'))"
  True None None
  $ ls -l config.json | cut -c1-10
  -rw-------

Verify subsequent command works via the oracle-held session key
  $ pfa -c config.json auth list -q
  1
