idbctl config
INVITATION=$(idbctl admin initialize)
ssh-keygen -t ed25519 -f account -N "" > /dev/null
idbctl accept --invitation $INVITATION --key account
ssh-keygen -t ed25519 -f session -N "" > /dev/null
idbctl login --session-key session
