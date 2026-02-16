# Create Boundary
idbctl admin boundary create -n boundary

# Create tag
idbctl admin tag create -n id -v person
idbctl admin tag create -n id -v device
PERSON_ID=$(idbctl admin tag list -n id -v person -q)
DEVICE_ID=$(idbctl admin tag list -n id -v device -q)

# Create role
idbctl admin role create -n role
ROLE_ID=$(idbctl admin role list -n role -q)

# Create identity user1
idbctl admin identity create -n user1
USER1_ID=$(idbctl admin identity list -n user1 -q)
INVITATION=$(idbctl admin identity invite -i $USER1_ID --manual)
echo $INVITATION

# Create identity user2
idbctl admin identity create -n user2
USER2_ID=$(idbctl admin identity list -n user2 -q)

# Add identity to role
idbctl admin role member -i $ROLE_ID -a user1

# New user accepts invitation and logs in
DIRECTORY_URL=http://127.0.0.1:$API_PORT/idb/directory
idbctl -c user1.json config --directory $DIRECTORY_URL
ssh-keygen -t ed25519 -f user1 -N "" > /dev/null
idbctl -c user1.json accept --invitation $INVITATION --key user1
ssh-keygen -t ed25519 -f user1-session -N "" > /dev/null
idbctl -c user1.json login --session-key user1-session
