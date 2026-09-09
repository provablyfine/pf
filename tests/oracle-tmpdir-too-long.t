Long $TMPDIR makes the session-key oracle refuse to start with a clear error,
rather than silently falling back to cleartext session-key storage.
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account
  $ unset SSH_AUTH_SOCK; unset SSH_AGENT_PID
  $ pf -c config.json login
  Unable to start session-key signing oracle: \$TMPDIR is too long to hold a pf session-oracle socket \(.*\); unset it or point it at a shorter path (re)
  [2]
