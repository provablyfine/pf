DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/t/root/directory
pf -c config.json config --directory $DIRECTORY_URL
INVITATION=$(pfa -c config.json initialize)
echo $INVITATION
ssh-keygen -t ed25519 -f account -N "" > /dev/null
pf -c config.json accept --invitation=$INVITATION --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
pf -c config.json login --session-key session
