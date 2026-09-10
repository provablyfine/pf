Initialize with file account key
  $ DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null
  $ pfa -c config.json initialize $DIRECTORY_URL --key account

`uv run pf` is not supported
  $ unset SSH_AUTH_SOCK; unset SSH_AGENT_PID
  $ uv run --project "$REPO_ROOT" --no-sync pf -c config.json login
  pf was launched by uv/uvx.* (re)
  Install pf.* (re)
