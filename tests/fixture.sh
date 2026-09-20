DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/00000000-0000-0000-0000-000000000001/directory
ssh-keygen -t ed25519 -f account -N "" > /dev/null
pfa -c config.json initialize $DIRECTORY_URL --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
pfa -c config.json login --session-key session
echo "."
