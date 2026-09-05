Case: create a password-protected account key (issue #91)
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ printf "hunter22\nhunter22\nhunter22\n" | pfa -c config.json initialize $DIRECTORY_URL 2>/dev/null
  Account key saved to */.ssh/pf_* (glob)
  $ printf "hunter22\n" | pfa -c config.json login 2>/dev/null
  $ pfa -c config.json auth list -q
  1
