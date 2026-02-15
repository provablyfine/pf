DIRECTORY_URL=http://127.0.0.1:$API_PORT/idb/directory
idbctl config --directory $DIRECTORY_URL
INVITATION=$(idbctl admin initialize)
echo $INVITATION
ssh-keygen -t ed25519 -f account -N "" > /dev/null
idbctl accept --invitation $INVITATION --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
idbctl login --session-key session
