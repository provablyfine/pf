Case 1: read a password-protected account key (issue #91)
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "hunter22" > /dev/null
  $ printf "hunter22\n" | pfa -c config.json initialize $DIRECTORY_URL --key account 2>/dev/null
  $ ssh-keygen -t ed25519 -f session -N "" > /dev/null
  $ printf "hunter22\n" | pfa -c config.json login --session-key session 2>/dev/null
  $ pfa -c config.json auth list -q
  1
