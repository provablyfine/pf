DIRECTORY_URL=http://127.0.0.1:$API_PORT/pf/directory
pf config --directory $DIRECTORY_URL
INVITATION=$(pfa initialize)
echo $INVITATION
ssh-keygen -t ed25519 -f account -N "" > /dev/null
pf accept --invitation=$INVITATION --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
pf login --session-key session
