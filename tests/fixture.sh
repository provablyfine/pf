idbctl config --directory http://127.0.0.1:$SERVER_PORT/idb/directory
INVITATION=$(idbctl admin initialize)
ssh-keygen -t ed25519 -f account -N "" > /dev/null
idbctl accept --invitation $INVITATION --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
idbctl login --session-key session
